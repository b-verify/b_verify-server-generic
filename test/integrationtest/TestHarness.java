package integrationtest;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import client.MockClient;
import crpyto.CryptographicSignature;
import org.junit.Assert;
import log.BVerifyLog;
import serialization.generated.BVerifyAPIMessageSerialization.LogProof;
import server.BVerifyServer;

public class TestHarness {
	private static final Logger logger = Logger.getLogger(TestHarness.class.getName());

	private final List<MockClient> clientLogs;
	private final int nStatementsPerLog;
	private final int batchSize;
	private final int correctNumberOfCommitments;
	private final boolean checkSignatures;

	public TestHarness(int nLogs, int nStatementsPerLog, int batchSize, boolean checkSignatures) {
		this.nStatementsPerLog = nStatementsPerLog;
		this.batchSize = batchSize;
		this.checkSignatures = checkSignatures;	
		int totalStatements = nLogs*(1+nStatementsPerLog);
		if(totalStatements % batchSize != 0) {
			throw new RuntimeException("bad test parameters, will leave uncomitted updates");
		}
		if(nLogs < batchSize) {
			throw new RuntimeException("bad test parameters, will result in rejected updates");
		}
		this.correctNumberOfCommitments = 1+(totalStatements / this.batchSize);
		this.clientLogs = new ArrayList<>();
		KeyPair kp = CryptographicSignature.generateNewKeyPair();
		for (int i = 0; i < nLogs; i++) {
			String logName = "LOG " + i;
			this.clientLogs.add(new MockClient(kp, logName, checkSignatures));
		}
	
	}

	public void runTest() {
		logger.log(Level.INFO, "running test with " + this.clientLogs.size() + "logs and " + this.nStatementsPerLog
				+ "statements per log");
		BVerifyServer server = new BVerifyServer(this.batchSize, this.checkSignatures);
		// create the logs
		for (MockClient mc : this.clientLogs) {
			boolean accepted = server.createNewLog(mc.getCreateLogStatement());
			if (!accepted) {
				Assert.fail("log not created");
			}
		}
		logger.log(Level.INFO, "...logs created");
		// make the statements
		for (int i = 0; i < nStatementsPerLog; i++) {
			String stmt = "S" + i;
			for (MockClient mc : this.clientLogs) {
				boolean accepted = server.makeLogStatement(mc.addLogStatement(stmt));
				if (!accepted) {
					Assert.fail("statement not accepted");
				}
			}
		}
		logger.log(Level.INFO, "...statements added");
		// get the commitments
		List<byte[]> commitments = server.commitments();
		if(this.correctNumberOfCommitments != commitments.size()) {
			Assert.fail("incorrect number of commitments. Had "+commitments.size()+
					" should have "+this.correctNumberOfCommitments);
		}
		
		// check the proofs
		logger.log(Level.INFO, "...checking proofs");
		for (MockClient mc : this.clientLogs) {
			LogProof lp = server.getLogProof(mc.getLogID());
			try {
				BVerifyLog bverifylog = new BVerifyLog(lp, this.checkSignatures);
				boolean correctStmts = deepEquals(bverifylog.getLogStatements(), mc.getLogStatements());
				boolean correctCmts = deepEquals(bverifylog.getCommittments(), commitments);
				if (!correctStmts) {
					Assert.fail("failed! incorrect statments in log");
				}
				if (!correctCmts) {
					Assert.fail("failed! incorrect commitments");
				}
			} catch (Exception e) {
				Assert.fail("failed! bad proof");
			}
		}
	}

	public static boolean deepEquals(List<byte[]> a, List<byte[]> b) {
		if (a.size() != b.size()) {
			return false;
		}
		for (int i = 0; i < a.size(); i++) {
			if (!Arrays.equals(a.get(i), b.get(i))) {
				return false;
			}
		}
		return true;
	}

}