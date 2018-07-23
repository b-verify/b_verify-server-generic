package client;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.CreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.LogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class ClientLog {
	
	private final KeyPair keypair;
	private final List<String> statements;
	private final byte[] logID;
	private final SignedCreateLogStatement signedCreateLogStmt;
	private final List<SignedLogStatement> signedLogStmts;
	
	public ClientLog(KeyPair kp, String initStmt) {
		this.keypair = kp;
		this.signedLogStmts = new ArrayList<>();
		this.statements = new ArrayList<>();
		CreateLogStatement createLogStmt = CreateLogStatement.newBuilder()
				.setInitialStatement(ByteString.copyFrom(initStmt.getBytes()))
				.setControllingPublicKey(
						ByteString.copyFrom(this.keypair.getPublic().getEncoded()))
				.build();
		this.logID = CryptographicDigest.hash(createLogStmt.toByteArray());
		byte[] signature = CryptographicSignature.sign(this.logID, this.keypair.getPrivate());
		SignedCreateLogStatement signedCreateLogStmt = SignedCreateLogStatement.newBuilder()
				.setCreateLogStatement(createLogStmt)
				.setSignature(ByteString.copyFrom(signature))
				.build();
		this.signedCreateLogStmt = signedCreateLogStmt;
		this.statements.add(initStmt);
	}
	
	public SignedCreateLogStatement getSignedCreateLogStmt() {
		return this.signedCreateLogStmt;
	}
	
	public SignedLogStatement addSignedLogStatement(String newStmt) {
		this.statements.add(newStmt);
		LogStatement stmt = LogStatement.newBuilder().setLogId(ByteString.copyFrom(this.logID))
				.setStatment(ByteString.copyFrom(newStmt.getBytes()))
				.setIndex(this.getNextStatementIdx())
				.build();
		byte[] witness = CryptographicDigest.hash(stmt.toByteArray());
		byte[] signature = CryptographicSignature.sign(witness, this.keypair.getPrivate());
		SignedLogStatement signedLogStmt = SignedLogStatement.newBuilder().setStatement(stmt)
				.setSignature(ByteString.copyFrom(signature))
				.build();
		this.signedLogStmts.add(signedLogStmt);
		return signedLogStmt;
	}
	
	public SignedLogStatement getSignedLogStatements(int i ) {
		return this.signedLogStmts.get(i);
	}
	
	public byte[] getLogID() {
		return this.logID;
	}
	
	private int getNextStatementIdx() {
		return this.statements.size();
	}
	
	@Override
	public String toString() {
		String res = "<LogID: "+Utils.byteArrayAsHexString(logID)+"\n";
		int i = 0;
		for(String s : this.statements) {
			res+="		#"+i+" - "+s+"\n";
		}
		res+=">";
		return res;
	}
}


















