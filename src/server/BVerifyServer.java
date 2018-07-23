package server;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class BVerifyServer {
	private static final Logger logger = Logger.getLogger(BVerifyServer.class.getName());
	
	/** 
	 * 	 Components
	 */
	private final LogManager logManager;
		
	public BVerifyServer(int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, "...starting a b_verify server"
				+ " (batch size: "+batchSize+" | require signatures: "+requireSignatures+")");
		this.logManager = new LogManager(batchSize, requireSignatures);	
	} 
	
	/**
	 * 	API Endpoints (can be exported via JAVA RMI)
	 */
	
	public boolean createNewLog(SignedCreateLogStatement signedCreateLogStatement) {
		return this.logManager.commitNewLog(signedCreateLogStatement);
	}
	
	public boolean makeLogStatement(SignedLogStatement newSignedStatement) {
		return this.logManager.commitNewLogStatement(newSignedStatement);
	}
	
	public LogProof getLogProof(byte[] logId) {
		return this.logManager.getLogProof(logId);
	}

	public List<byte[]> commitments() {
		return this.logManager.getCommitments();
	}
	
}
