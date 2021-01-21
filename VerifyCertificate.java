import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Base64;
import java.util.Base64.Decoder;

public class VerifyCertificate {

    
    public static X509Certificate getCertificate(String Certificate) throws IOException, CertificateException {
        InputStream inStream = null;
        X509Certificate cert;
        try {
            inStream = new FileInputStream(Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert;
    }

    public static X509Certificate getCertificateByContent(String Certificate) throws IOException, CertificateException {
        InputStream inStream = null;
        X509Certificate cert;
        Decoder decoder = Base64.getDecoder();
        try {
            inStream = new ByteArrayInputStream(decoder.decode(Certificate));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert;
    }

    public static PublicKey getPublicKeyFromCertFile(String Certificate) throws FileNotFoundException, CertificateException {
        FileInputStream fileInputStream = new FileInputStream(Certificate);
        X509Certificate x509Certificate = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(fileInputStream);
        return x509Certificate.getPublicKey();
    }

    public static void getVerify(X509Certificate CA, X509Certificate User) throws Exception {
        try {
            CA.checkValidity();
            User.checkValidity();
            CA.verify(CA.getPublicKey());
            User.verify(CA.getPublicKey());
            System.out.println("Pass");
        }
        catch(Exception E){
            System.out.println("Fail");
            System.out.println(E.toString());
            throw new Exception();
        }

    }

    public static void verifyHandshake(String ca, String user) throws Exception {
        try {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            X509Certificate CA = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(ca.getBytes(StandardCharsets.UTF_8)));
            X509Certificate CA = getCertificate(ca);
            X509Certificate User = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(user)));
            CA.checkValidity();
            User.checkValidity();
            CA.verify(CA.getPublicKey());
            User.verify(CA.getPublicKey());
            System.out.println("Pass");
        }
        catch(Exception E){
            System.out.println("Fail");
            System.out.println(E.toString());
            throw new Exception();
        }
    }

    public static X509Certificate createCertificate(String Certificate) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte [] CertByte = java.util.Base64.getDecoder().decode(Certificate);
        InputStream inStrem = new ByteArrayInputStream(CertByte);
        return (X509Certificate) cf.generateCertificate(inStrem);
    }

    public static void main(String[] args) throws Exception {

//        String CA = args[0];
//        String user = args[1];

//        System.out.println(getCertificate(CA).getSubjectDN());
//        System.out.println(getCertificate(user).getSubjectDN());
//
        String CA = "cert-file/ca/myCA.pem";
        String user = "cert-file/client/client-cert.pem";

        System.out.println(getCertificate(CA).getSubjectDN());
        System.out.println(getCertificate(user).getSubjectDN());
        getVerify(getCertificate("cert-file/ca/myCA.pem"), getCertificate("cert-file/client/client-cert.pem"));
        VerifyCertificate.verifyHandshake(
                CA,
                new String(Files.readAllBytes(Paths.get(user)))
                );
    }

}