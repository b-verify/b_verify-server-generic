package client;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import log.BVerifyLog;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.CreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.LogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class MockClient {

	private final KeyPair ownerKeyPair;
	private final List<byte[]> statements;
	private final byte[] logID;
	private final boolean sign;

	private final SignedCreateLogStatement signedCreateLogStmt;
	private final List<SignedLogStatement> signedLogStmts;

	public MockClient(KeyPair ownerKeyPair, String initStmt, boolean sign) {
		byte[] initStmtAsBytes = initStmt.getBytes();
		this.ownerKeyPair = ownerKeyPair;
		this.sign = sign;
		this.signedLogStmts = new ArrayList<>();
		this.statements = new ArrayList<>();
		CreateLogStatement createLogStmt = CreateLogStatement.newBuilder()
				.setInitialStatement(ByteString.copyFrom(initStmtAsBytes))
				.setControllingPublicKey(ByteString.copyFrom(this.ownerKeyPair.getPublic().getEncoded())).build();
		this.logID = CryptographicDigest.hash(createLogStmt.toByteArray());
		if(this.sign) {
			byte[] signature = CryptographicSignature.sign(this.logID, this.ownerKeyPair.getPrivate());
			this.signedCreateLogStmt = SignedCreateLogStatement.newBuilder()
					.setCreateLogStatement(createLogStmt).setSignature(ByteString.copyFrom(signature)).build();
		}else {
			this.signedCreateLogStmt = SignedCreateLogStatement.newBuilder()
					.setCreateLogStatement(createLogStmt).build();
		}
		this.statements.add(initStmt.getBytes());
	}

	public SignedCreateLogStatement getCreateLogStatement() {
		return this.signedCreateLogStmt;
	}

	public SignedLogStatement addLogStatement(String newStmt) {
		byte[] stmtBytes = newStmt.getBytes();
		LogStatement stmt = LogStatement.newBuilder().setLogId(ByteString.copyFrom(this.logID))
				.setStatment(ByteString.copyFrom(stmtBytes)).setIndex(this.getNextStatementIdx()).build();
		byte[] witness = CryptographicDigest.hash(stmt.toByteArray());
		SignedLogStatement signedLogStmt;
		if(this.sign) {
			byte[] signature = CryptographicSignature.sign(witness, this.ownerKeyPair.getPrivate());
			signedLogStmt = SignedLogStatement.newBuilder().setStatement(stmt)
					.setSignature(ByteString.copyFrom(signature)).build();
		}else {
			signedLogStmt = SignedLogStatement.newBuilder().setStatement(stmt).build();
		}
		this.statements.add(stmtBytes);
		this.signedLogStmts.add(signedLogStmt);
		return signedLogStmt;
	}

	public SignedLogStatement getLogStatement(int i) {
		return this.signedLogStmts.get(i);
	}

	public byte[] getLogID() {
		return this.logID;
	}

	public List<byte[]> getLogStatements() {
		return new ArrayList<>(this.statements);
	}

	private int getNextStatementIdx() {
		return this.statements.size();
	}

	@Override
	public String toString() {
		String res = "<LogID: " + Utils.byteArrayAsHexString(logID) + "\n";
		int i = 0;
		for (byte[] s : this.statements) {
			res += "		#" + i + " - " + BVerifyLog.bytesToString(s) + "\n";
		}
		res += ">";
		return res;
	}
}
