package integrationtest;

import org.junit.Test;

public class BVerifyServerTest {
		
	/**
	 * Tests of correct behavior
	 */
	
	@Test
	public void testSingleLog() {
		int nLogs = 1;
		int nStatementsPerLog = 20;
		int batchSize = 1;
		boolean requireSigs = true;
		TestHarness test = new TestHarness(nLogs, nStatementsPerLog, 
				batchSize, requireSigs); 
		test.runTest();
	}
	
	@Test
	public void testManyLogs() {
		int nLogs = 10;
		int nStatementsPerLog = 10;
		int batchSize = 1;
		boolean requireSigs = true;
		TestHarness test = new TestHarness(nLogs, nStatementsPerLog, 
				batchSize, requireSigs); 
		test.runTest();
	}
	
	@Test
	public void testManyLogsBatched() {
		int nLogs = 20;
		int nStatementsPerLog = 10;
		int batchSize = 10;
		boolean requireSigs = true;
		TestHarness test = new TestHarness(nLogs, nStatementsPerLog, 
				batchSize, requireSigs); 
		test.runTest();
	}
	
	@Test
	public void testLargeTest() {
		int nLogs = 1000;
		int nStatementsPerLog = 1;
		int batchSize = 100;
		boolean requireSigs = false;
		TestHarness test = new TestHarness(nLogs, nStatementsPerLog, 
				batchSize, requireSigs); 
		test.runTest();
	}
	
	/**
	 * Attacks
	 */
	
	

	
}










