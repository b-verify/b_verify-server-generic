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
	private final PublicKey ownerPublicKey;
	private final List<byte[]> witnesses;
	private final List<byte[]> statements;
	
	private final LogProof proof;
	
	public BVerifyLog(LogProof proof) throws Exception {
		this.proof = proof;
		
		SignedCreateLogStatement signedCreateLogStmt = this.proof.getCreateLogStatement();
		this.logID = getLogID(signedCreateLogStmt);
		this.ownerPublicKey = getOwnerPublicKey(signedCreateLogStmt);
		// now check the proof		
		
		// first check the signatures on the statements
		// and calculate the witnesses
		this.witnesses = new ArrayList<>();
		this.statements = new ArrayList<>();
		
		if(!verifySignature(signedCreateLogStmt)) {
			throw new RuntimeException("bad proof");
		}
		this.witnesses.add(getWitness(signedCreateLogStmt));
		this.statements.add(getStatement(signedCreateLogStmt));
		for(SignedLogStatement s : proof.getSignedStatementsList()) {
			if(!verifySignature(s, this.ownerPublicKey, this.logID)) {
				throw new RuntimeException("bad proof");
			}
			this.witnesses.add(getWitness(s));
			this.statements.add(getStatement(s));
		}
		
		System.out.println("STATEMENTS: ");
		for(byte[] stmt : this.statements) {
			System.out.println(" --> "+new String(stmt, Charset.forName("UTF-8")));
		}
		System.out.println("WITNESSES: ");
		for(byte[] witness : this.witnesses) {
			System.out.println(" --> "+Utils.byteArrayAsHexString(witness));
		}
		
		// second check the Merkle proofs
		MPTDictionaryPartial path = MPTDictionaryPartial.deserialize(proof.getProofOfStatements(0));
		System.out.println("PROOFS: ");
		System.out.println("index: 0");
		byte[] getInit = path.get(logID);
		byte[] cmtInit = path.commitment();
		if(getInit != null) {
			System.out.println("Get --> "+Utils.byteArrayAsHexString(getInit));
		}else {
			System.out.println("Get --> NULL");
		}
		System.out.println("CMT --> "+Utils.byteArrayAsHexString(cmtInit));
		for(int i = 1; i < proof.getProofOfStatementsCount(); i++) {
			path.processUpdates(proof.getProofOfStatements(i));
			System.out.println("index: "+i);
			byte[] get = path.get(logID);
			byte[] cmt = path.commitment();
			if(get != null) {
				System.out.println("Get --> "+Utils.byteArrayAsHexString(get));
			}else {
				System.out.println("Get --> NULL");
			}
			System.out.println("CMT --> "+Utils.byteArrayAsHexString(cmt));
		}
		
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
	
	public static byte[] getWitness(SignedLogStatement s) {
		return CryptographicDigest.hash(s.toByteArray());
	}
	
	public static byte[] getWitness(SignedCreateLogStatement s) {
		return CryptographicDigest.hash(s.toByteArray());
	}
	
	public static boolean verifySignature(SignedCreateLogStatement signedCreateLogStmt) {
		CreateLogStatement stmt = signedCreateLogStmt.getCreateLogStatement();
		PublicKey pk = getOwnerPublicKey(stmt);
		byte[] logID = getLogID(stmt);
		byte[] signature = signedCreateLogStmt.getSignature().toByteArray();
		return CryptographicSignature.verify(logID, signature, pk);
	}
	
	public static boolean verifySignature(SignedLogStatement signedLogStmt, PublicKey owner, byte[] logId) {
		if(Arrays.equals(logId, getLogID(signedLogStmt))) {
			byte[] toSign = CryptographicDigest.hash(signedLogStmt.getStatement().toByteArray());
			byte[] signature = signedLogStmt.getSignature().toByteArray();
			return CryptographicSignature.verify(toSign, signature, owner);
		}
		return false;
	}
	
}
