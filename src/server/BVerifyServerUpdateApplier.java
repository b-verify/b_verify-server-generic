package server;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.time.LocalDateTime;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is a single threaded applier that 
 * stages updates. After TARGET_BATCH_SIZE updates 
 * have been performed, the applier thread freezes the 
 * handler by acquiring the write lock, applies all outstanding 
 * entries and commits them. 
 * @author henryaspegren
 *
 */
public class BVerifyServerUpdateApplier implements Runnable {
	private static final Logger logger = Logger.getLogger(BVerifyServerUpdateApplier.class.getName());

	/**
	 * Parameters - batching, impact performance
	 */
	private int totalLogs;
	private int totalLogStatements;
	private int totalUpdates;
	private int uncommittedUpdates;
	private final int TARGET_BATCH_SIZE;
	
	// TODO also add a timeout so that things always eventually get
	//			committed
	
	/**
	 * Shared data!
	 */
	private final ReadWriteLock lock;
	private final BlockingQueue<Update> updatesToCommit;
	private final LogManager logManager;
	
	private boolean shutdown;
	
	/**
	 * Workers for parallelizing commitment work
	 */
	private final ExecutorService workers = Executors.newCachedThreadPool();
		
	public BVerifyServerUpdateApplier(ReadWriteLock lock, BlockingQueue<Update> updatesToCommit,
			LogManager logManager, 
			int batchSize) {
		this.lock = lock;
		this.updatesToCommit = updatesToCommit;
		this.logManager = logManager;
		this.TARGET_BATCH_SIZE = batchSize;
		this.totalLogs = 0;
		this.totalLogStatements = 0;
		this.totalUpdates = 0;
		this.uncommittedUpdates = 0;
		this.shutdown = false;

		try {
			// process any initializing updates, if any
			logger.log(Level.INFO, "... processing "+this.updatesToCommit.size()+" initial log creation statements ");
			while(!this.updatesToCommit.isEmpty()) {
				Update update = this.updatesToCommit.take();
				if(!update.isCreateLogStatement()) {
					logger.log(Level.INFO, "... error - a log statement has been recieved before the log has been created");
					throw new RuntimeException();
				}
				this.logManager.commitNewLog(update.getSignedCreateLogStatement());
				this.totalLogs++;
				this.totalUpdates++;
				if(this.totalLogs % 10000 == 0) {
					logger.log(Level.INFO, "..."+this.totalLogs+" logs initialized");
				}
			}
			logger.log(Level.INFO, "doing initial commit!");
			this.logManager.commitParallelized(this.workers);		
			logger.log(Level.INFO, "initialized "+this.totalLogs
					+" logs [at "+LocalDateTime.now()+"]");
		}catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}
		
		
	}
	
	/**
	 * Call this method to safely shutdown the update applier thread
	 */
	public void setShutdown() {
		this.shutdown = true;
	}
	
	@Override
	public void run() {
		try {
			while(!this.shutdown) {
				// we use poll here to make sure that the shutdown condition is checked 
				// at least once a second
				Update update = this.updatesToCommit.poll(1, TimeUnit.SECONDS);
				if(update == null) {
					continue;
				}
				if(update.isCreateLogStatement()) {
					this.logManager.commitNewLog(update.getSignedCreateLogStatement());
					this.totalLogs++;
				}else {
					this.logManager.commitNewLogStatement(update.getSignedLogStatement());
					this.totalLogStatements++;
				}					
				this.totalUpdates++;
				this.uncommittedUpdates++;
				logger.log(Level.FINE, "uncommitted updates: "+this.uncommittedUpdates);
				
				if(this.uncommittedUpdates % 10000 == 0) {
					logger.log(Level.INFO, "... batched currently: "+this.uncommittedUpdates);
				}
				
				// once we hit the batch size, trigger a commit
				// 
				if(this.uncommittedUpdates == this.TARGET_BATCH_SIZE) {
					// stop accepting requests by getting the WRITE LOCK
					this.lock.writeLock().lock();
					// drain any approved updates (since have lock, no more will get added,
					// but there may be some existing updates outstanding)
					while(!this.updatesToCommit.isEmpty()) {
						Update lastUpdate = this.updatesToCommit.take();
						if(lastUpdate.isCreateLogStatement()) {
							this.logManager.commitNewLog(lastUpdate.getSignedCreateLogStatement());
							this.totalLogs++;
						}else {
							this.logManager.commitNewLogStatement(lastUpdate.getSignedLogStatement());
							this.totalLogStatements++;
						}	
						this.totalUpdates++;
						this.uncommittedUpdates++;
						logger.log(Level.FINE, "staging update #"+totalUpdates);
					}
					// once all outstanding updates are added
					// commit!
					int totalNumberOfNodes = this.logManager.countTotalNumberOfNodes();
					int totalNumberOfHashesNeededToCommit = this.logManager.countHashesNeededToCommit();
					logger.log(Level.INFO, "starting to commit");
					logger.log(Level.INFO, "[total updates: "+uncommittedUpdates+
							" | total nodes in MPT: "+totalNumberOfNodes+
							" | number of hashes needed to commit: "+totalNumberOfHashesNeededToCommit+
							"]");
					long startTime = System.currentTimeMillis();
					this.logManager.commitParallelized(this.workers);		
					long endTime = System.currentTimeMillis();
					this.lock.writeLock().unlock();
					long duration = endTime - startTime;
					NumberFormat formatter = new DecimalFormat("#0.000");
					String timeTaken = formatter.format(duration / 1000d)+ " seconds";
					logger.log(Level.INFO, "time taken to commit: "+timeTaken);
					logger.log(Level.INFO, "logs: "+this.totalLogs+" | statements: "+this.totalLogStatements
						+"total updates: "+totalUpdates+" [at "+LocalDateTime.now()+"]");
					this.uncommittedUpdates = 0;
				}
			}	
			logger.log(Level.INFO, "...shutting down applier workers");
			this.workers.shutdown();
			try {
			    if (!this.workers.awaitTermination(800, TimeUnit.MILLISECONDS)) {
			    	this.workers.shutdownNow();
			    } 
			} catch (InterruptedException e) {
				this.workers.shutdownNow();
} 
		} catch(InterruptedException e) {
			e.printStackTrace();
			logger.log(Level.WARNING, "something is wrong...shutdown");
			throw new RuntimeException(e.getMessage());
		}
	}
	
}
