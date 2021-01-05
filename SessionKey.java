import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;




public class SessionKey {

    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(keylength);
        this.secretKey = KeyGen.generateKey();
    }


    public SessionKey(byte[] Keybytes) {
        this.secretKey = new SecretKeySpec(Keybytes,"AES");
       
      }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public byte[] getKeyBytes()  {
     
    	return this.secretKey.getEncoded();
    	    }
 
}

