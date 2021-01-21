import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private static final String METHOD = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private Cipher cipher;

    public SessionEncrypter(Integer length) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.sessionKey = new SessionKey(length);
        this.cipher = Cipher.getInstance(METHOD);
        this.cipher.init(1, this.sessionKey.getSecretKey());
    }

    public SessionEncrypter(String keyBytes, String ivBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher = Cipher.getInstance(METHOD);
        this.sessionKey = new SessionKey(keyBytes);
        this.cipher.init(1, this.sessionKey.getSecretKey(), new IvParameterSpec(
                Base64.getDecoder().decode(ivBytes)
        ));
    }

    public byte[] getKeyBytes() {
        return this.sessionKey.getSecretKey().getEncoded();
    }

    public byte[] getIVBytes() {
        return this.cipher.getIV();
    }
    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, this.cipher);
    }

    public String encodeKey() {
        return this.sessionKey.encodeKey();
    }

    public String encodeIV() {
        byte[] iv = this.cipher.getIV();
        return Base64.getEncoder().encodeToString(iv);
    }
}