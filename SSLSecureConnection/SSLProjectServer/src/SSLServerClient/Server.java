package SSLServerClient;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class Server {

    //Member variables
    private ServerSocket serverSock = null;
    private Socket socketToClient;
    int portNumber;

    /**
     * serverSocket constructor
     * sets the port number, and opens the socket channel
     *
     * @param portNumberIn
     * @throws Exception
     */
    public Server(int portNumberIn) throws Exception {
        portNumber = portNumberIn;
        if (portNumberIn <= 0) {
            throw new Exception("Port number was not entered.");
        }
        serverSock = new ServerSocket(portNumberIn);
    }

    /**
     * This serves the socket and opens the connection
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void serve() throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        while (true) {
            socketToClient = serverSock.accept();
            ServerUtils.openCertificate(socketToClient);
            ServerUtils.createCertificate(socketToClient);
            //
//            OutputStream outMessage = socketToClient.getOutputStream();
//            PrintWriter scanOut = new PrintWriter(outMessage);
//            System.out.println("at print writer");
//            scanOut.println("You Made It!");
//            scanOut.flush();
            //
//            InputStream ins = socketToClient.getInputStream();
////            Scanner scan = new Scanner(ins);
////            while(scan.hasNextLine()) {
//////                String thing = scan.nextLine();
////                System.out.println(scan.nextLine());
////            }
            try {
                ServerUtils.decrypt(socketToClient); //**
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            ServerUtils.createSharedSecret();
            ServerUtils.sendHash(socketToClient, ServerUtils.computeHash1());
            ServerUtils.compareHash(socketToClient);
            ServerUtils.create4Keys();
            ServerUtils.sendFile(socketToClient);
            ServerUtils.sendEncryptedFile(socketToClient);
        }
    }
}
