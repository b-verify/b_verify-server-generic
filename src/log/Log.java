package log;

import java.security.PublicKey;
import java.util.List;

import mpt.core.Utils;

public class Log {
	
	private final PublicKey owner;
	private final byte[] logID;
	private final List<String> statements;
	
	public Log(byte[] logID, PublicKey owner, List<String> statements) {
		this.logID = logID;
		this.owner = owner;
		this.statements = statements;
	}
	
	public byte[] getID() {
		return this.logID;
	}
	
	public PublicKey getOwner() {
		return this.owner;
	}
	
	public List<String> getStatements(){
		return this.statements;
	}
	
	@Override
	public String toString() {
		String res = "<LogID: "+Utils.byteArrayAsHexString(this.logID)+"\n"
				+"Owner:"+this.owner.toString()+"\n";
		int i = 0;
		for(String s : this.statements) {
			res+="		#"+i+" - "+s+"\n";
		}
		res+=">";
		return res;
	}

}
