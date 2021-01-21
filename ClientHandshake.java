/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public String sessionHost = "localhost";
    public int sessionPort = 12345;

    public SessionDecrypter sessionDecrypter;
    public SessionEncrypter sessionEncrypter;
    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 
    public ClientHandshake(Socket handshakeSocket){
        try {
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.putParameter("MessageType", "ClientHello");
            clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get(
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
            sessionHost = session.getProperty("SessionHost");
            sessionPort = Integer.parseInt(session.getProperty("SessionPort"));


            Encoder encoder = Base64.getEncoder();
            Decoder decoder = Base64.getDecoder();
            sessionEncrypter = new SessionEncrypter(
                    encoder.encodeToString(
                            HandshakeCrypto.decrypt(
                                    decoder.decode(session.getProperty("SessionKey")),
                                    HandshakeCrypto.getPrivateKeyFromKeyFile(ForwardClient.getArgument().get("key"))
                                    )
                    ),
                    encoder.encodeToString(
                            HandshakeCrypto.decrypt(
                                    decoder.decode(session.getProperty("SessionIV")),
                                    HandshakeCrypto.getPrivateKeyFromKeyFile(ForwardClient.getArgument().get("key"))
                            )
                    )
            );
            sessionDecrypter = new SessionDecrypter(
                    sessionEncrypter.encodeKey(),
                    sessionEncrypter.encodeIV()
            );

        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
