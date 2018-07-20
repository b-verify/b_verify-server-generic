package server;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

/**
 * Locking Discipline + Concurrency: the client API can be exposed for
 * concurrent calls, but whenever a commit happens, lock.writeLock is acquired
 * by the applier thread, and the API should be frozen while the commit takes
 * place
 * 
 * @author henryaspegren
 *
 */
public class BVerifyServerRequestVerifier {
	private static final Logger logger = Logger.getLogger(BVerifyServerRequestVerifier.class.getName());

	/**
	 * Shared data!
	 */
	private final ReadWriteLock lock;
	private final LogManager logManager;
	private final BlockingQueue<Update> updatesToBeCommitted;

	/**
	 * Optionally can disable the checking of signatures to speed test cases
	 */
	private final boolean requireSignatures;

	public BVerifyServerRequestVerifier(ReadWriteLock lock, BlockingQueue<Update> updatesToBeCommitted, 
			LogManager logManager, boolean requireSignatures) {
		this.lock = lock;
		this.logManager = logManager;
		this.updatesToBeCommitted = updatesToBeCommitted;
		this.requireSignatures = requireSignatures;
	}

	
	public boolean createNewLog(SignedCreateLogStatement signedCreateLogStatement) {
		logger.log(Level.FINE, "new create log request recieved: "+signedCreateLogStatement);
		this.lock.readLock().lock();
		if(this.requireSignatures) {
			if(!this.logManager.verifyCreateLog(signedCreateLogStatement)) {
				this.lock.readLock().unlock();
				logger.log(Level.WARNING, "create log request not valid, bad signatures");
			}
		}
		this.updatesToBeCommitted.add(new Update(signedCreateLogStatement));
		logger.log(Level.FINE, "log created");
		this.lock.readLock().unlock();
		return true;
	}
	
	public boolean makeLogStatement(SignedLogStatement newSignedStatement) {
		logger.log(Level.FINE, "new log statement request recieved: "+newSignedStatement);
		this.lock.readLock().lock();
		if (this.requireSignatures) {
			if (!this.logManager.verifyNewLogStatement(newSignedStatement)) {
				logger.log(Level.WARNING, "new log statement not valid, bad signatures");
				this.lock.readLock().unlock();
				return false;
			}
		}
		this.updatesToBeCommitted.add(new Update(newSignedStatement));
		this.lock.readLock().unlock();
		logger.log(Level.FINE, "new statement accepted");
		return true;
	}

	public LogProof getLogProof(byte[] logId) {
		logger.log(Level.FINE, "prove log request recieved");
		this.lock.readLock().lock();
		LogProof proof = this.logManager.getLogProof(logId);
		this.lock.readLock().unlock();
		return proof;
	}
	
	public List<byte[]> commitments() {
		logger.log(Level.FINE, "get commitments request recieved");
		this.lock.readLock().lock();
		List<byte[]> commitments = this.logManager.getCommitments();
		this.lock.readLock().unlock();
		return commitments;
	}


}
