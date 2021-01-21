import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


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

    public SessionKey(String s) {
        byte[] decode = Base64.getDecoder().decode(s);
        this.secretKey = new SecretKeySpec(decode, "AES");
    }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public byte[] getKeyBytes()  {
     
    	return this.secretKey.getEncoded();
    	    }

    public String encodeKey() {
        byte[] encoded = this.secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }
}

