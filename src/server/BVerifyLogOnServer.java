package server;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.CreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class BVerifyLogOnServer {

	private final byte[] logID;
	private final PublicKey ownerPublicKey;
	private final SignedCreateLogStatement signedCreateLogStatement;
	private final List<SignedLogStatement> signedLogStatements;
				
	public BVerifyLogOnServer(SignedCreateLogStatement createLogStmt) {
		this.signedCreateLogStatement = createLogStmt;
		CreateLogStatement stmt = createLogStmt.getCreateLogStatement();
		this.ownerPublicKey = CryptographicSignature.loadPublicKey(
				stmt.getControllingPublicKey().toByteArray());
		this.logID = CryptographicDigest.hash(stmt.toByteArray());
		this.signedLogStatements = new ArrayList<>();
	}
	
	public static boolean verifySignature(SignedCreateLogStatement createLogStmt) {
		CreateLogStatement stmt = createLogStmt.getCreateLogStatement();
		PublicKey pk = CryptographicSignature.loadPublicKey(
				stmt.getControllingPublicKey().toByteArray());
		byte[] logID = CryptographicDigest.hash(stmt.toByteArray());
		byte[] signature = createLogStmt.getSignature().toByteArray();
		return CryptographicSignature.verify(logID, signature, pk);
	}
	
	public static boolean verifySignature(SignedLogStatement signedLogStmt, PublicKey owner, byte[] logId) {
		if(Arrays.equals(logId, signedLogStmt.getStatement().getLogId().toByteArray())) {
			byte[] witness = CryptographicDigest.hash(signedLogStmt.getStatement().toByteArray());
			byte[] signature = signedLogStmt.getSignature().toByteArray();
			return CryptographicSignature.verify(witness, signature, owner);
		}
		return false;
	}
	
	public void addLogStatement(SignedLogStatement s) {
		this.signedLogStatements.add(s);
	}
	
	public List<SignedLogStatement> getSignedLogStatements(){
		return this.signedLogStatements;
	}
	
	public SignedCreateLogStatement getSignedCreateLogStatement() {
		return this.signedCreateLogStatement;
	}
	
	public int numberOfStatements() {
		return this.signedLogStatements.size();
	}
	
	public byte[] getID() {
		return this.logID;
	}
	
	public PublicKey getOwnerPublicKey() {
		return this.ownerPublicKey;
	}
	
	public LogProof.Builder getProofBuilder() {
		return LogProof.newBuilder().setCreateLogStatement(this.signedCreateLogStatement)
				.addAllSignedStatements(this.signedLogStatements);
	}
	
	@Override
	public String toString() {
		String res = "<logID: "+Utils.byteArrayAsHexString(this.logID)
				+" controlled by: "+this.ownerPublicKey
				+" with "+this.numberOfStatements()+" statements>";
		return res;
	}
	
}
