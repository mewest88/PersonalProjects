package SSLClient;

public class SSLClientMain {

    public static void main(String[] args) throws Exception {

        System.out.println("SSL Request Client");

        //Set the port number with the value input while calling executable
//        int portNo = Integer.parseInt(args[0]);
        int portNo = 8080;

        Client clientSocket = new Client(portNo);
//        clientSocket.createCertificate(newRequest);

    }
}
