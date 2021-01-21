import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    private static final String METHOD = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private Cipher cipher;

    public SessionDecrypter(String s, String s1) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.sessionKey = new SessionKey(s);
        this.cipher = Cipher.getInstance(METHOD);
        byte[] decode = Base64.getDecoder().decode(s1);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decode);
        this.cipher.init(2, this.sessionKey.getSecretKey(), ivParameterSpec);
    }

    public CipherInputStream openCipherInputStream(InputStream input) {
        return new CipherInputStream(input, this.cipher);
    }
}