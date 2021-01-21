import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher ciph = Cipher.getInstance("RSA");
        ciph.init(Cipher.ENCRYPT_MODE,key);

        return ciph.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher ciph = Cipher.getInstance("RSA");
        ciph.init(Cipher.DECRYPT_MODE,key);

        return ciph.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException {
        InputStream inStream = null;
        X509Certificate cert;
        try {
            inStream = new FileInputStream(certfile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } finally{
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert.getPublicKey();
    }

    public static PublicKey getPublicKeyFromCertString(String certString) throws IOException, CertificateException {
        InputStream inStream = null;
        X509Certificate cert = null;
        try {
            inStream =  new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8));;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pKeyByte = Files.readAllBytes(Paths.get(keyfile));
        PKCS8EncodedKeySpec kSpec = new PKCS8EncodedKeySpec(pKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey Pkey = keyFactory.generatePrivate(kSpec);

        return Pkey;
    }

    public static PrivateKey getPrivateKeyFromKeyString(String keyString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pKeyByte = keyString.getBytes();
        PKCS8EncodedKeySpec kSpec = new PKCS8EncodedKeySpec(pKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey Pkey = keyFactory.generatePrivate(kSpec);

        return Pkey;
    }
}
