package server;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * 
 * It efficiently stores each of the logs and the associated proofs.
 * 
 * Each log consists of the following:
 * 
 * 	type:	[CreateLogStatement, LogStatement, LogStatement .... ]
 * 	index:			0					1			2
 * 	log ID: H(CreateLogStatement)
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
	 * (Merkle Prefix Trie and previous versions as deltas)
	 * 
	 */
	private final MPTDictionaryFull mpt;
	private final List<MPTDictionaryDelta> mptdeltas;

	/*
	 * COMMITMENTS
	 * (normally these would be witnessed to Bitcoin
	 * 	since the code to create and broadcast 
	 * 	a Bitcoin tx is pretty trivial we omit it)
	 */
	private final List<byte[]> commitments;
	
	/*
	 * PARAMETERS
	 * 		 - for batching, and performance benchmarking
	 * TODO also add a timeout so that things always eventually get
	 * 	committed
	 */
	private int uncommittedUpdates;
	private final Set<ByteBuffer> logIDsWithUncomittedModifications;
	private final int TARGET_BATCH_SIZE;	
	private final boolean REQUIRE_SIGNATURES;
	private int totalLogs;
	private int totalLogStatements;

	public LogManager(int batchSize, boolean requireSigs) {
		logger.log(Level.INFO, "...creating LogManager");
		this.logIdToLog = new HashMap<>();
		this.logIDsWithUncomittedModifications = new HashSet<>();
		// initialize the stats to
		logger.log(Level.INFO, "...initializing stats");
		this.totalLogs = 0;
		this.totalLogStatements = 0;
		this.uncommittedUpdates = 0;
		this.TARGET_BATCH_SIZE = batchSize;
		this.REQUIRE_SIGNATURES = requireSigs;
		logger.log(Level.INFO, "...initializing empty authentication information");
		this.mpt = new MPTDictionaryFull();
		this.mptdeltas = new ArrayList<>();
		this.commitments = new ArrayList<>();		
		logger.log(Level.INFO, "...log manager created");
	}
	
	// safe for concurrent calls
	public boolean verifySignatureSignedCreateLogStatement(SignedCreateLogStatement signedCreateLogStmt) {
		return BVerifyLog.verifyCreateLogStatement(signedCreateLogStmt);
	}
	
	// safe for concurrent calls 
	public boolean verifyNewLogStatement(SignedLogStatement signedStmt) {
		byte[] logID = BVerifyLog.getLogID(signedStmt);
		PublicKey pk = this.logIdToLog.get(ByteBuffer.wrap(logID)).getOwnerPublicKey();
		return BVerifyLog.verifyLogStatement(signedStmt, pk, logID);
	}
	
	public boolean commitNewLog(SignedCreateLogStatement signedCreateStmt) {
		logger.log(Level.INFO, "...attempting to create a new log");
		
		// signature verification (parallelized)
		boolean signed = verifySignatureSignedCreateLogStatement(signedCreateStmt);
		if(!signed && this.REQUIRE_SIGNATURES) {
			logger.log(Level.WARNING, "...rejected because not properly signed");
			return false;
		}
		
		// create a new log (parallelized)
		BVerifyLogOnServer newLog = new BVerifyLogOnServer(signedCreateStmt);
		byte[] logID = newLog.getID();
		ByteBuffer logIDKey = ByteBuffer.wrap(logID);
		byte[] witness = BVerifyLog.getSignedStatementHash(signedCreateStmt);
		
		// need mutex to actually add the log, and perform final verification 
		// since concurrent creation of logs or modification of mpt is not safe
		synchronized(this) {
			if(this.logIdToLog.containsKey(logIDKey)) {
				logger.log(Level.WARNING, "...rejected because already created this log");
				return false;
			}
			if(this.logIDsWithUncomittedModifications.contains(logIDKey)) {
				logger.log(Level.WARNING, "...rejected because already have a create request for this log id");
				return false;
			}
			
			// accepted, create the log
			this.logIDsWithUncomittedModifications.add(logIDKey);
			this.logIdToLog.put(logIDKey, newLog);
			this.mpt.insert(logID, witness);
			this.totalLogs++;
			this.totalLogStatements++;
			this.uncommittedUpdates++;
			
			// commit if we have a full batch
			if(this.uncommittedUpdates == this.TARGET_BATCH_SIZE) {
				this.commit();
			}
		}
		
		logger.log(Level.INFO, "...new log "+Utils.byteArrayAsHexString(logID)+" created");
		return true;
	}
		
	public boolean commitNewLogStatement(SignedLogStatement newLogStatement) {	
		logger.log(Level.INFO, "attempting to add a new statement to the log");
		
		// verify the signature (parallelized)
		boolean signed = this.verifyNewLogStatement(newLogStatement);
		if(!signed && this.REQUIRE_SIGNATURES) {
			logger.log(Level.WARNING, "... rejected because not properly signed");
			return false;
		}
		byte[] logID = BVerifyLog.getLogID(newLogStatement);
		ByteBuffer logIDKey = ByteBuffer.wrap(logID);
		int statementNumber = BVerifyLog.getStatementIndex(newLogStatement);
		
		// need mutex to actually add it to the log
		// and check that it has correct index
		synchronized(this) {
			if(!this.logIdToLog.containsKey(logIDKey)) {
				logger.log(Level.WARNING, "...rejected because no such log exists");
				return false;
			}
			if(this.logIDsWithUncomittedModifications.contains(logIDKey)) {
				logger.log(Level.WARNING, "...rejected because already have an uncommitted statement for this log");
				return false;
			}
			
			BVerifyLogOnServer log = this.logIdToLog.get(logIDKey);
			int correctStatementNumber = log.getLastStatementIndex()+1;
			if(correctStatementNumber != statementNumber) {
				logger.log(Level.WARNING, "...rejected because statement #"+statementNumber
						+" but should be "+correctStatementNumber);
			}
			log.addLogStatement(newLogStatement);
			this.logIdToLog.put(logIDKey, log);
			this.logIDsWithUncomittedModifications.add(logIDKey);
			byte[] witness = BVerifyLog.getSignedStatementHash(newLogStatement);
			this.mpt.insert(logID, witness);
			this.totalLogStatements++;
			this.uncommittedUpdates++;
			// commit if we have enough updates
			if(this.uncommittedUpdates == this.TARGET_BATCH_SIZE) {
				this.commit();
			}
		}
		logger.log(Level.INFO, "...added statement #"+statementNumber+" to log "+Utils.byteArrayAsHexString(logID));
		return true;
	}
		
	public void commit() {
		logger.log(Level.INFO, "...committing!");
		// print info for benchmarking
		// and time the commitment
		int totalNumberOfNodes = this.mpt.countNodes();
		int totalNumberOfHashesNeededToCommit = this.mpt.countHashesRequiredToCommit();;
		logger.log(Level.INFO, "...[total updates to commit: "+this.uncommittedUpdates+
				" | total nodes in MPT: "+totalNumberOfNodes+
				" | number of hashes needed to commit: "+totalNumberOfHashesNeededToCommit+
				"]");
		long startTime = System.currentTimeMillis();
		
		// actual commit procedure
		// update required data structures, add the commitment
		MPTDictionaryDelta delta = new MPTDictionaryDelta(this.mpt);
		this.mptdeltas.add(delta);
		this.mpt.reset();
		
		// Normally this commitment would also be witnessed to Bitcoin
		// but for clarity and modularity, that code must 
		// be included elsewhere
		byte[] commitment = this.mpt.commitment();
		
		this.commitments.add(commitment);
		this.logIDsWithUncomittedModifications.clear();
		this.uncommittedUpdates = 0;
		
		long endTime = System.currentTimeMillis();
		long duration = endTime - startTime;
		// print the stats
		NumberFormat formatter = new DecimalFormat("#0.000");
		String timeTaken = formatter.format(duration / 1000d)+ " seconds";
		logger.log(Level.INFO, "...time taken to commit: "+timeTaken);
		logger.log(Level.INFO, "...[logs: "+this.totalLogs+" | statements: "+this.totalLogStatements
			+" | at "+LocalDateTime.now()+"]");
		logger.log(Level.INFO, "...commitment #"+this.getCurrentCommitmentNumber()+": "+Utils.byteArrayAsHexString(commitment));
	}
	
	public LogProof getLogProof(byte[] logId) {
		logger.log(Level.INFO, "...log proof request recieved");
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
