/**
 * Server side of the handshake.
 */

import java.net.Socket;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public static SessionEncrypter sessionEncrypter = new SessionEncrypter(128);

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket) throws Exception {
        sessionSocket = new ServerSocket(22345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();

        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(handshakeSocket);
        VerifyCertificate.verifyHandshake(
                ForwardServer.getArguments().get("cacert"),
                clientHello.getParameter("Certificate"));

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.putParameter("MessageType", "ServerHello");
        serverHello.putParameter("Certificate",
                new String(Files.readAllBytes(Paths.get(ForwardServer.getArguments().get("usercert")))));
        serverHello.send(handshakeSocket);

        HandshakeMessage forward = new HandshakeMessage();
        forward.recv(handshakeSocket);
        targetHost = forward.getParameter("TargetHost");
        targetPort = Integer.parseInt(forward.getParameter("TargetPort"));

        HandshakeMessage session = new HandshakeMessage();
        session.putParameter("MessageType", "Session");
        session.putParameter("SessionHost", sessionHost);
        session.putParameter("SessionPort", String.valueOf(sessionPort));
        session.putParameter("SessionKey", Arrays.toString(
                HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(),
                        HandshakeCrypto.getPublicKeyFromCertString(
                        clientHello.getParameter("Certificate"))
                )));
        session.putParameter("SessionIV", Arrays.toString(sessionEncrypter.getIVBytes()));
        session.send(handshakeSocket);

        System.out.println("handshake is completed");
    }
}
