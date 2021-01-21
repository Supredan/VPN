/**
 * Server side of the handshake.
 */

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public ServerSocket sessionSocket;
    public String sessionHost;
    public int sessionPort;

    /* The final destination -- simulate handshake with constants */
    public String targetHost = "localhost";
    public int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
    public SessionDecrypter sessionDecrypter;
    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket) throws Exception {
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(handshakeSocket);
        HandshakeMessage.checkMessageType(clientHello, "ClientHello");
        clientHello.list(System.out);
        VerifyCertificate.verifyHandshake(
                ForwardServer.getArguments().get("cacert"),
                clientHello.getParameter("Certificate"));
        X509Certificate clientCertificate = VerifyCertificate.getCertificateByContent(
                clientHello.getParameter("Certificate"));

        X509Certificate serverCertificate = VerifyCertificate.getCertificate(
                ForwardServer.getArguments().get("usercert"));
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter("MessageType", "ServerHello");
        serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCertificate.getEncoded()));
        serverHello.send(handshakeSocket);

        HandshakeMessage forward = new HandshakeMessage();
        forward.recv(handshakeSocket);
        HandshakeMessage.checkMessageType(forward, "Forward");
        targetHost = forward.getParameter("TargetHost");
        targetPort = Integer.parseInt(forward.getParameter("TargetPort"));

        HandshakeMessage session = new HandshakeMessage();
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(), sessionEncrypter.encodeIV());
        session.putParameter("MessageType", "Session");
        session.putParameter("SessionHost", InetAddress.getLocalHost().getHostAddress());
        sessionSocket = new ServerSocket();
        sessionSocket.bind(null);
        Encoder encoder = Base64.getEncoder();
        session.putParameter("SessionPort", Integer.toString(sessionSocket.getLocalPort()));
        session.putParameter("SessionKey", encoder.encodeToString(
                HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(),
                        clientCertificate.getPublicKey())));
        session.putParameter("SessionIV", encoder.encodeToString(
                HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(),
                        clientCertificate.getPublicKey())));
        session.send(handshakeSocket);

        System.out.println("handshake is completed");
    }
}
