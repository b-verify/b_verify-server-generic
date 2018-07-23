package log;

import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryPartial;
import serialization.generated.BVerifyAPIMessageSerialization.CreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import serialization.generated.BVerifyAPIMessageSerialization.LogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class BVerifyLog {

	private final byte[] logID;
	private final PublicKey owner;
	private final List<byte[]> witnesses;
	private final List<byte[]> statements;
	private final List<byte[]> commitments;
	
	private final LogProof proof;
	
	public BVerifyLog(LogProof proof, boolean requireSignatures) throws Exception {
		this.proof = proof;
		
		SignedCreateLogStatement signedCreateLogStmt = this.proof.getCreateLogStatement();
		this.logID = getLogID(signedCreateLogStmt);
		this.owner = getOwnerPublicKey(signedCreateLogStmt);
		
		// PART 1: 
		// go through the log statements, 
		// verify the signatures, and compute the witnesses
		
		this.witnesses = new ArrayList<>();
		this.statements = new ArrayList<>();
		this.commitments = new ArrayList<>();
		
		if(!verifyCreateLogStatement(signedCreateLogStmt, requireSignatures)) {
			throw new Exception("create log statement not signed, proof rejected");
		}

		this.witnesses.add(getSignedStatementHash(signedCreateLogStmt));
		this.statements.add(getStatement(signedCreateLogStmt));
		
		for(SignedLogStatement s : proof.getSignedStatementsList()) {
			if(!verifyLogStatement(s, this.owner, this.logID, requireSignatures)) {
				throw new RuntimeException("bad proof");
			}
			this.witnesses.add(getSignedStatementHash(s));
			this.statements.add(getStatement(s));
		}
		
		// PART 2:
		// check the Merkle proofs and calcualte the 
		// commitments (the commitments should match what 
		// has been witnessed in Bitcoin)
		
		MPTDictionaryPartial path = MPTDictionaryPartial.deserialize(proof.getProofOfStatements(0));	
		// server should start with no logs
		byte[] currentWitness = null;
		int currentWitnessIdx = -1;
		if(!(currentWitness == path.get(logID))) {
			throw new RuntimeException("bad proof");
		}
		this.commitments.add(path.commitment());
		for(int i = 1; i < proof.getProofOfStatementsCount(); i++) {
			path.processUpdates(proof.getProofOfStatements(i));
			byte[] get = path.get(logID);
			if(!Arrays.equals(currentWitness, get)) {
				if(currentWitnessIdx+1 >= this.witnesses.size()) {
					throw new Exception("bad proof, incorrect witnesss");
				}
				byte[] nextWitness = this.witnesses.get(currentWitnessIdx+1);
				if(!Arrays.equals(nextWitness, get)) {
					throw new Exception("bad proof, incorrect witnesss");
				}
				currentWitness = nextWitness;
				currentWitnessIdx++;
			}
			this.commitments.add(path.commitment());
		}
		
	}
	
	public List<byte[]> getLogStatements(){
		return new ArrayList<>(this.statements);
	}
	
	public byte[] getLogStatement(int i){
		if( i < 0 || i >= this.statements.size()) {
			return null;
		}else {
			return this.statements.get(i);
		}
	}
	
	public byte[] getCommitment(int i){
		if( i < 0 || i >= this.commitments.size()) {
			return null;
		}else {
			return this.commitments.get(i);
		}
	}
	
	public List<byte[]> getCommittments(){
		return new ArrayList<>(this.commitments);
	}
	
	@Override
	public String toString() {
		String res = "<LogID: "+Utils.byteArrayAsHexString(this.logID)+"\n"
				+"Owner: \n		"+this.owner.toString()+"\n";
		res+="Statements: \n";
		int i = 0;
		for(byte[] s : this.statements) {
			res+="		S"+i+" - "+bytesToString(s)+"\n";
			i++;
		}
		res+="Commitments: \n";
		i = 0;
		for(byte[] c : this.commitments) {
			res+="		C"+i+" - "+Utils.byteArrayAsHexString(c)+"\n";
			i++;
		}
		res+=">";
		return res;
	}
	
	public static String bytesToString(byte[] bs) {
		return new String(bs, Charset.forName("UTF-8"));
	}
	
	public static int getStatementIndex(SignedLogStatement s) {
		return getStatementIndex(s.getStatement());
	}
	
	public static int getStatementIndex(LogStatement s) {
		return s.getIndex();
	}
	
	public static byte[] getStatement(SignedCreateLogStatement s) {
		return getStatement(s.getCreateLogStatement());
	}
	
	public static byte[] getStatement(CreateLogStatement s) {
		return s.getInitialStatement().toByteArray();
	}
	
	public static byte[] getStatement(SignedLogStatement s) {
		return getStatement(s.getStatement());
	}
	
	public static byte[] getStatement(LogStatement s) {
		return s.getStatment().toByteArray();
	}
	
	public static PublicKey getOwnerPublicKey(SignedCreateLogStatement s) {
		return getOwnerPublicKey(s.getCreateLogStatement());
	}
	
	public static PublicKey getOwnerPublicKey(CreateLogStatement createLogStmt) {
		return CryptographicSignature.loadPublicKey(
				createLogStmt.getControllingPublicKey().toByteArray());
	}
	
	public static byte[] getLogID(SignedCreateLogStatement s) {
		return getLogID(s.getCreateLogStatement());
	}
	public static byte[] getLogID(CreateLogStatement createLogStmt) {
		return CryptographicDigest.hash(createLogStmt.toByteArray());
	}
	
	public static byte[] getLogID(SignedLogStatement s) {
		return getLogID(s.getStatement());
	}
	
	public static byte[] getLogID(LogStatement stmt) {
		return stmt.getLogId().toByteArray();
	}
	
	public static byte[] getStatementHash(SignedLogStatement s) {
		return getStatementHash(s.getStatement());
	}
	
	public static byte[] getStatementHash(LogStatement s) {
		return CryptographicDigest.hash(s.toByteArray());
	}
	
	public static byte[] getSignedStatementHash(SignedLogStatement s) {
		return CryptographicDigest.hash(s.toByteArray());
	}
	
	public static byte[] getSignedStatementHash(SignedCreateLogStatement s) {
		return CryptographicDigest.hash(s.toByteArray());
	}
	
	public static boolean verifyCreateLogStatement(SignedCreateLogStatement signedCreateLogStmt, boolean requireSignatures) {
		if(requireSignatures) {
			CreateLogStatement stmt = signedCreateLogStmt.getCreateLogStatement();
			PublicKey pk = getOwnerPublicKey(stmt);
			byte[] logID = getLogID(stmt);
			byte[] signature = signedCreateLogStmt.getSignature().toByteArray();
			return CryptographicSignature.verify(logID, signature, pk);
		}
		return true;
	}
	
	public static boolean verifyLogStatement(SignedLogStatement signedLogStmt, PublicKey owner, byte[] logId, boolean requireSignatures) {
		if(Arrays.equals(logId, getLogID(signedLogStmt))) {
			if(requireSignatures) {
				byte[] toSign = CryptographicDigest.hash(signedLogStmt.getStatement().toByteArray());
				byte[] signature = signedLogStmt.getSignature().toByteArray();
				return CryptographicSignature.verify(toSign, signature, owner);
			}
			return true;
		}
		return false;
	}
	
}
