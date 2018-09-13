package SSLClient;

import java.net.InetAddress;
import java.net.Socket;

public class Client {

    //Member Variables
    int portNumber;
    private Socket socketToClient;

    public Client(int portNumberUsed) throws Exception {
//        System.out.println("in client constructor");
        portNumber = portNumberUsed;
        if(portNumberUsed <= 0) {
            throw new Exception("Port number was not entered.");
        }
        InetAddress host = InetAddress.getLocalHost();
//        System.out.println(host);
        socketToClient = new Socket(host, portNumberUsed);
        ClientUtils.createCertificate(socketToClient);
        ClientUtils.openCertificate(socketToClient);
//        ClientUtils.decrypt(newRequest);
        ClientUtils.generateNonce(socketToClient); //creates the nonce and send the nonce too
        ClientUtils.createSharedSecret();
        ClientUtils.compareHash(socketToClient);
        ClientUtils.sendHash(socketToClient, ClientUtils.computeHash2(ClientUtils.computeHash1()));
        ClientUtils.create4Keys();
        ClientUtils.readFile(socketToClient);
        ClientUtils.readEncryptedFile(socketToClient);
    }
}
