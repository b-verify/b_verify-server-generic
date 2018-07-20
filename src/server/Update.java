package server;

import serialization.generated.BVerifyAPIMessageSerialization.SignedCreateLogStatement;
import serialization.generated.BVerifyAPIMessageSerialization.SignedLogStatement;

public class Update {
	
	private SignedLogStatement logStmt;
	private SignedCreateLogStatement createStmt;
	
	public Update(SignedLogStatement s) {
		this.logStmt = s;
	}
	
	public Update(SignedCreateLogStatement c) {
		this.createStmt = c;
	}
	
	public boolean isSignedLogStatement() {
		return this.logStmt != null;
	}
	
	public boolean isCreateLogStatement() {
		return !this.isSignedLogStatement();
	}
	
	public SignedLogStatement getSignedLogStatement() {
		return this.logStmt;
	}
	
	public SignedCreateLogStatement getSignedCreateLogStatement() {
		return this.createStmt;
	}
}
