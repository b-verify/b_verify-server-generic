package crpyto;

/**
 * This class contains the various cryptographic commitments and mappings used
 * by the b_verify protocol
 * 
 * @author henryaspegren
 *
 */
public class CryptographicUtils {

	/**
	 * Commits to a key and a value using the following commitment
	 * 
	 * H(key||value)
	 * 
	 * @param key
	 * @param value
	 * @return
	 */
	public static byte[] witnessKeyAndValue(byte[] key, byte[] value) {
		byte[] witnessPreImage = new byte[key.length + value.length];
		System.arraycopy(key, 0, witnessPreImage, 0, key.length);
		System.arraycopy(value, 0, witnessPreImage, key.length, value.length);
		byte[] witness = CryptographicDigest.hash(witnessPreImage);
		return witness;
	}
	
	/**
	 * TODO - need to finalize what this will look like
	 * 
	 * Used to calculate the witness for a server update
	 * 
	 * @param authRoot
	 *            - the root of the authentication ADS, required in case of
	 *            coordinating commits across multiple ADSes.
	 * @return
	 */
	public static byte[] witnessUpdate(byte[] authRoot) {
		byte[] witness = CryptographicDigest.hash(authRoot);
		return witness;
	}

}
