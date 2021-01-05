/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;    

    /* Security parameters key/iv should also go here. Fill in! */
    public static String clientCertPath = "./cert-file/client/client.pem";
    public static SessionDecrypter sessionDecrypter;

    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 
    public ClientHandshake(Socket handshakeSocket){
        try {
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.putParameter("MessageType", "ClientHello");
            clientHello.putParameter("Certificate", new String(Files.readAllBytes(Paths.get(
                    ForwardClient.getArgument().get("usercert")))));
            clientHello.send(handshakeSocket);

            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.recv(handshakeSocket);
            VerifyCertificate.verifyHandshake(
                    ForwardClient.getArgument().get("cacert"),
                    serverHello.getParameter("Certificate"));

            HandshakeMessage forward = new HandshakeMessage();
            forward.putParameter("MessageType", "Forward");
            forward.putParameter("TargetHost", ForwardClient.getArgument().get("targethost"));
            forward.putParameter("TargetPort", ForwardClient.getArgument().get("targetport"));
            forward.send(handshakeSocket);

            HandshakeMessage session = new HandshakeMessage();
            session.recv(handshakeSocket);
            sessionHost = session.getParameter("SessionHost");
            sessionPort = Integer.parseInt(session.getParameter("SessionPort"));
            sessionDecrypter = new SessionDecrypter(
                    HandshakeCrypto.decrypt(session.getParameter("SessionKey").getBytes(),
                            HandshakeCrypto.getPrivateKeyFromKeyString(
                                    ForwardClient.getArgument().get("usercert")
                            )),
                    session.getParameter("SessionIV").getBytes()
            );
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
