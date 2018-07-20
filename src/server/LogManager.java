package server;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import log.BVerifyLog;
import mpt.core.Utils;
import mpt.dictionary.MPTDictionaryDelta;
import mpt.dictionary.MPTDictionaryFull;
import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

/**
 * This class is responsible for managing log data.
 * It efficiently stores each of the logs and the associated proofs.
 * 
 * Each log consists of the following:
 * 
 * 		[CreateLogStatement, LogStatement, LogStatement .... ]
 * 	
 * and the log ID to identify the log is H(CreateLogStatement)
 * 
 * The proof consists of 
 * 
 * 		[SignedCreateLogStatement, SignedLogStatement, SignedLogStatement, ...] 
 * 	
 * 										+ 
 * 
 * 							Merkle Proofs to Commitments
 * 				
 * 
 * @author henryaspegren
 *
 */
public class LogManager {
	private static final Logger logger = Logger.getLogger(LogManager.class.getName());
	
	/*
	 * LOG DATA
	 */
	private final Map<ByteBuffer, BVerifyLogOnServer> logIdToLog;	
	
	/*
	 * AUTHENTICATION INFORMATION 
	 * (MERKLE PREFIX TRIE)
	 * 
	 */
	
	// current Merkle Prefix Trie
	private MPTDictionaryFull mpt;
	// previous versions of the Merkle Prefix Trie (as deltas)
	private final List<MPTDictionaryDelta> mptdeltas;

	// commitments
	// (normally these would be witnessed to Bitcoin
	// 	since this code is pretty trivial we omit it)
	private List<byte[]> commitments;

	public LogManager() {
		this.logIdToLog = new HashMap<>();
		logger.log(Level.INFO, "...initializing empty authentication information");
		this.mpt = new MPTDictionaryFull();
		this.mptdeltas = new ArrayList<>();
		this.commitments = new ArrayList<>();		
		logger.log(Level.INFO, "log manager created");
	}
	
	public PublicKey getLogOwners(byte[] logId){
		return this.logIdToLog.get(ByteBuffer.wrap(logId)).getOwnerPublicKey();
	}
	
	public boolean verifyCreateLog(SignedCreateLogStatement signedCreateStmt) {
		return BVerifyLogOnServer.verifySignature(signedCreateStmt);
	}
	
	public boolean verifyNewLogStatement(SignedLogStatement signedStmt) {
		byte[] logID = signedStmt.getStatement().getLogId().toByteArray();
		PublicKey pk = this.logIdToLog.get(ByteBuffer.wrap(logID)).getOwnerPublicKey();
		return BVerifyLogOnServer.verifySignature(signedStmt, pk, logID);
	}
	
	public void commitNewLog(SignedCreateLogStatement signedCreateStmt) {
		// create a new log 
		BVerifyLogOnServer newLog = new BVerifyLogOnServer(signedCreateStmt);
		this.logIdToLog.put(ByteBuffer.wrap(newLog.getID()), newLog);
		// update the MPT
		byte[] witness = BVerifyLog.getWitness(signedCreateStmt);
		this.mpt.insert(newLog.getID(), witness);
		logger.log(Level.INFO, "... new log "+Utils.byteArrayAsHexString(newLog.getID())+" created");
	}
		
	public void commitNewLogStatement(SignedLogStatement newLogStatement) {
		// lookup the log
		byte[] logID = newLogStatement.getStatement().getLogId().toByteArray();
		ByteBuffer logIDKey = ByteBuffer.wrap(logID);
		BVerifyLogOnServer log = this.logIdToLog.get(logIDKey);
		// add the statement to the log
		log.addLogStatement(newLogStatement);
		this.logIdToLog.put(logIDKey, log);
		// update the MPT
		byte[] witness = BVerifyLog.getWitness(newLogStatement);
		this.mpt.insert(logID, witness);
		logger.log(Level.INFO, "... statement #"+log.numberOfStatements()+" added to log "+Utils.byteArrayAsHexString(log.getID()));
	}
	
	public int countHashesNeededToCommit() {
		return this.mpt.countHashesRequiredToCommit();
	}
	
	public int countTotalNumberOfNodes() {
		return this.mpt.countNodes();
	}
	
	public byte[] commit() {
		return this.commitParallelized(null);
	}
	
	public byte[] commitParallelized(ExecutorService workers) {
		logger.log(Level.FINE, "committing!");
		// save delta and clear any changes
		MPTDictionaryDelta delta = new MPTDictionaryDelta(this.mpt);
		this.mptdeltas.add(delta);
		this.mpt.reset();
		
		// calculate a new commitment
		byte[] commitment;
		if(workers != null) {
			commitment = this.mpt.commitmentParallelized(workers);
		}else {
			commitment = this.mpt.commitment();
		}
		
		this.commitments.add(commitment);
		logger.log(Level.INFO, "added commitment #"+this.getCurrentCommitmentNumber()+": "+Utils.byteArrayAsHexString(commitment));
		return commitment;
	}
	
	public LogProof getLogProof(byte[] logId) {
		ByteBuffer key = ByteBuffer.wrap(logId);
		LogProof.Builder proof = this.logIdToLog.get(key).getProofBuilder();
		// add the authentication information
		// to complete the proof 
		for(MPTDictionaryDelta delta : this.mptdeltas) {
			proof.addProofOfStatements(delta.getUpdates(logId));
		}
		return proof.build();
	}
		
	public int getCurrentCommitmentNumber() {
		return this.commitments.size()-1;
	}
	
	public List<byte[]> getCommitments(){
		return new ArrayList<>(this.commitments);
	}
	
}
