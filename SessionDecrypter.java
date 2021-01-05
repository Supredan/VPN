import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;

public class SessionDecrypter {
    private static final String METHOD = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private Cipher cipher;
    private IvParameterSpec ivParameterSpec;

    public SessionDecrypter (byte[] keybytes, byte[] ivbytes) {
        try {
            this.sessionKey = new SessionKey(keybytes);
            this.cipher = Cipher.getInstance(METHOD);
            this.ivParameterSpec = new IvParameterSpec(ivbytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public CipherInputStream openCipherInputStream(InputStream input) {
        try {
            this.cipher.init(Cipher.DECRYPT_MODE, this.sessionKey.getSecretKey(), this.ivParameterSpec);
            return new CipherInputStream(input, this.cipher);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}