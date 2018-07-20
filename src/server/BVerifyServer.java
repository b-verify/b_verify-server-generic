package server;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BVerifyServer {
	private static final Logger logger = Logger.getLogger(BVerifyServer.class.getName());
	
	/** 
	 * 	 Components
	 */
	private final BVerifyServerRequestVerifier verifier;
	private final BVerifyServerUpdateApplier applier;
	private final ExecutorService applierExecutor;
	
	/**
	 * Shared Data
	 */
	
	/*
	 * Lock is required for safety
	 */
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	
	/*
	 * Log Manager is responsible for management of the 
	 * core data structures.
	 */
	private final LogManager logManager;

	/*
	 * This is a shared queue using the producer-consumer 
	 * design pattern. This queue contains VERIFIED updates to be committed.
	 * Updates are added as they are verified and commitments are batched 
	 * for efficiency. 
	 */
	private BlockingQueue<Update> updatesToBeCommited;
		
	public BVerifyServer(int batchSize, boolean requireSignatures) {
		logger.log(Level.INFO, "staritng a b_verify server"
				+ " (batch size: "+batchSize+" | require signatures: "+requireSignatures+")");
		this.logManager = new LogManager();
		this.updatesToBeCommited = new LinkedBlockingQueue<>();
		this.verifier = 
				new BVerifyServerRequestVerifier(this.lock, this.updatesToBeCommited, this.logManager,
						requireSignatures);
		// now start up the applier 
		// which will automatically apply the initializing updates 
		this.applier = new BVerifyServerUpdateApplier(this.lock,
						this.updatesToBeCommited, this.logManager, batchSize);
		
		this.applierExecutor = Executors.newSingleThreadExecutor();
		this.applierExecutor.submit(this.applier);	
	} 
	
	public void shutdown() {
		logger.log(Level.INFO, "...shutting down the server");
		this.applier.setShutdown();
		this.applierExecutor.shutdown();
		try {
			this.applierExecutor.awaitTermination(10, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
			throw new RuntimeException(e.getMessage());
		}
	}
	
	// for testing only
	public BVerifyServerRequestVerifier getRequestHandler() {
		return this.verifier;
	}

}
