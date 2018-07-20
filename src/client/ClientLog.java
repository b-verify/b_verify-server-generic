package client;

import java.security.KeyPair;

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
	private final byte[] initialStatement;
	private final byte[] logID;
	private final CreateLogStatement createLogStmt;
	
	public ClientLog(KeyPair kp, byte[] init) {
		this.keypair = kp;
		this.initialStatement = init;
		this.createLogStmt = CreateLogStatement.newBuilder()
				.setInitialStatement(ByteString.copyFrom(this.initialStatement))
				.setControllingPublicKey(
						ByteString.copyFrom(this.keypair.getPublic().getEncoded()))
				.build();
		this.logID = CryptographicDigest.hash(this.createLogStmt.toByteArray());
	}
	
	public SignedCreateLogStatement getSignedCreateLogStmt() {
		byte[] signature = CryptographicSignature.sign(this.logID, this.keypair.getPrivate());
		SignedCreateLogStatement signedCreateLogStmt = SignedCreateLogStatement.newBuilder()
				.setCreateLogStatement(this.createLogStmt)
				.setSignature(ByteString.copyFrom(signature))
				.build();
		return signedCreateLogStmt;
	}
	
	public SignedLogStatement getSignedLogStatement(byte[] newStatement) {
		LogStatement stmt = LogStatement.newBuilder().setLogId(ByteString.copyFrom(this.logID))
				.setStatment(ByteString.copyFrom(newStatement))
				.build();
		byte[] witness = CryptographicDigest.hash(stmt.toByteArray());
		byte[] signature = CryptographicSignature.sign(witness, this.keypair.getPrivate());
		return SignedLogStatement.newBuilder().setStatement(stmt)
				.setSignature(ByteString.copyFrom(signature))
				.build();
	}
	
	public byte[] getLogID() {
		return this.logID;
	}
	
	@Override
	public String toString() {
		return "<LogID: "+Utils.byteArrayAsHexString(logID)+">";
	}
}
