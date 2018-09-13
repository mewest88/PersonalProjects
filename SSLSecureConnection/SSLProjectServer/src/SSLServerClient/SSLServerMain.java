package SSLServerClient;

public class SSLServerMain {

    public static void main(String[] args) throws Exception {

        System.out.println("SSL Request Server");
        System.out.println("Awaiting connection");

        //Set the port number with the value input while calling executable
//        int portNo = Integer.parseInt(args[0]);

        int portNo = 8080;

        Server serverSocket = new Server(portNo);
        serverSocket.serve();
    }
}
