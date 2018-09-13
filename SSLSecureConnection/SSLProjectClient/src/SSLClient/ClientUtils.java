package SSLClient;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ClientUtils {

    //public member variables
    public static PublicKey clientPubKey;
    public static PublicKey serverPubKey;
    public static PrivateKey clientPrivateKey;

    public static byte[] clientNonce;
    public static byte[] serverNonce;
    public static byte[] sharedSecret;

    public static SecretKey clientAuthKey;
    public static SecretKey  serverAuthKey;
    public static SecretKey clientEncKey;
    public static SecretKey serverEncKey;

    /**
     *  sends server cert and a nonce encrypted with client public key
     * send over the cert and flush the output stream and then send over the encrypted nonce
     * creates the cert using a certificate factory and sends it over the socket via an outputstream
     * @param socket
     * @throws IOException
     * @throws CertificateException
     */
    public static void createCertificate(Socket socket) throws IOException, CertificateException {
//        System.out.println("Starting createCertificate");
        FileInputStream fis = new FileInputStream("sslCertSigned.cert");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(fis);
        clientPubKey = cert.getPublicKey();
        OutputStream outsCert = socket.getOutputStream();
        outsCert.write(cert.getEncoded());
        outsCert.flush();
        System.out.println("Finishing createCertificate - cert sent");
//        System.out.println("cert");
//        System.out.println(cert.toString());
    }

    /**
     * Opens up a certificate sent over the socket. I also pulls the public key from the cert.
     * @param socket
     * @throws IOException
     * @throws CertificateException
     */
    public static void openCertificate(Socket socket) throws IOException, CertificateException {
//        System.out.println("Starting openCertificate");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(socket.getInputStream());
        serverPubKey = cert.getPublicKey();
//        System.out.println("cert");
//        System.out.println(cert.toString());
        //nonce test
//        DataInputStream nonce = new DataInputStream(socket.getInputStream());
//        int length = nonce.readInt();                    // read length of incoming message
//        if(length>0) {
//            byte[] message = new byte[length];
//            nonce.readFully(message, 0, message.length); // read the message
//            BigInteger bigIntNonce = new BigInteger(message);
//            System.out.println("nonce (big int version) = " + bigIntNonce);
//        }
//        System.out.print(nonce);
        //nonce = new BigInteger(new String(byte array))
        //nonce test end
        try {
            decrypt(socket);                        //calling decrypt here
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
//        System.out.println("Finishing openCertificate");
    }

    /**
     * generates a random nonce 8 bytes large using a SecureRandom generator
     * @param socket
     * @throws IOException
     */
    public static void generateNonce(Socket socket) throws IOException {
//        System.out.println("Starting generateNonce");
        SecureRandom rand = new SecureRandom();
        clientNonce = new byte[8];
        rand.nextBytes(clientNonce);
//        System.out.println("client nonce = " + toLong(clientNonce));
//        BigInteger nonce = new BigInteger(clientNonce);
//        System.out.println("client nonce " + nonce);
        byte[] encryptedNonce = encrypt(clientNonce);
//        BigInteger encryptedNonce = new BigInteger(clientNonce);
//        System.out.println("RSA encrypted nonce = " + encryptedNonce.toString());
        DataOutputStream outsNonce = new DataOutputStream(socket.getOutputStream());
//        outsNonce.writeInt(clientNonce.length);
        outsNonce.write(encryptedNonce);
        outsNonce.flush();
//        System.out.println("Finishing generateNonce");
    }

    /**
     * Creates a cipher and encrypts a byte array passed through
     * this is used specifically to encrypt the nonce in the handshake
     * @param nonce
     * @return
     */
    public static byte[] encrypt(byte[] nonce) {
//        System.out.println("Starting encrypt");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] encryptedNonce = null;
        try {
            encryptedNonce = cipher.doFinal(nonce);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
//        System.out.println("Finishing encrypt");
        return encryptedNonce;
    }

    /**
     * Starts with calling the extractPrivateKey method to obtain the servers private key.
     * Server then reads in the encrypted nonce through a DataInputStream. A Cipher is then used to decrypt the nonce
     * and the nonce is saved as a member variable.
     * @param socket
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static void decrypt(Socket socket) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//        System.out.println("Starting decrypt");
        extractPrivateKey();

        DataInputStream encryptedNonceIn = new DataInputStream(socket.getInputStream());
        byte[] encryptedServerNonce = new byte[256];
        encryptedNonceIn.readFully(encryptedServerNonce); // read the nonce
        BigInteger encryptedNonce = new BigInteger(encryptedServerNonce);
//        System.out.println("encrypted nonce from server(big int) = " + encryptedNonce);
//        System.out.println("encrypted nonce from server(long) = " + toLong(encryptedServerNonce));/
//            BigInteger bigIntNonce = new BigInteger(nonce);
//            System.out.println("nonce (big int version) = " + bigIntNonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA"); //**
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey); //**
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] decryptedNonce = null;
        try {
            decryptedNonce = cipher.doFinal(encryptedServerNonce); //**
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        serverNonce = decryptedNonce;
//        System.out.println("server nonce = " + toLong(serverNonce));
//        System.out.println("Finishing encrypt");
    }

    /**
     * loops through the serverNonce and the clientNonce to create the shared secret using the XOR
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static void extractPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//        System.out.println("Starting extractPrivateKey");
        File clientPrivKey = new File("prv.der");
        FileInputStream fis = null;
        fis = new FileInputStream(clientPrivKey);
        byte[] privKeyArray = new byte[(int)clientPrivKey.length()];
        fis.read(privKeyArray);
        fis.close();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(privKeyArray);
        clientPrivateKey = kf.generatePrivate(key);
//        System.out.println("client priv key = " + clientPrivateKey);
//        System.out.println("Finishing extractPrivateKey");
    }

    public static void createSharedSecret() {
        sharedSecret = new byte[clientNonce.length];
        for(int i = 0; i < serverNonce.length; i++) {
            sharedSecret[i] = (byte) (serverNonce[i] ^ clientNonce[i]);
        }
    }

    /**
     * Reads the clientHash in through a DataInputStream and compares the hashes with Arrays.equals().
     * The system exits if the hashes are not equal.
     * They system also reads in the messages CLIENT which follows the hash from the client.
     * @param socket
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static void compareHash(Socket socket) throws NoSuchAlgorithmException, IOException {
        //on the client, this needs to read in the servers sent hash1 and compare it to it's own computed hash1
        byte[] clientHash1 = computeHash1(); //create the clients hash
        DataInputStream serverHash1In = new DataInputStream(socket.getInputStream());
        byte[] serverHash1 = new byte[clientHash1.length];
        serverHash1In.readFully(serverHash1); // read the nonce
        assert clientHash1.length != serverHash1.length; //not the best use as this is error checking
//        if(clientHash1.length == serverHash1.length) {
//            System.out.println("The hashes are the same length!");
//        }
        assert Arrays.equals(clientHash1, serverHash1); //not the best use as this is error checking
        if(Arrays.equals(clientHash1, serverHash1)){
            System.out.println("The hashes are the same!");
        } else {
            System.out.println("The hashes are different");
            System.exit(-1);
        }
//        System.out.println("hash lengths: " + clientHash1.length);
//        System.out.println("client hash: " + clientHash1.toString());
//        System.out.println("server hash: " + serverHash1.toString());
//        System.out.println("client hash: " + toLong(clientHash1));
//        System.out.println("server hash: " + toLong(serverHash1));
//        BigInteger clientBIH = new BigInteger(clientHash1);
//        BigInteger serverBIH = new BigInteger(serverHash1);
//        System.out.println("client hash(BI): " + clientBIH);
//        System.out.println("server hash(BI): " + serverBIH);
        DataInputStream serverStringIn = new DataInputStream(socket.getInputStream());
        byte[] s = "SERVER".getBytes();
        byte[] serverString = new byte[s.length];
        serverStringIn.readFully(serverString); // read the nonce
        String SERVER = new String(serverString);
//        System.out.println("should say SERVER: " + SERVER);
        System.out.println("The hashes have been compared and are correct.");
    }

    /**
     * Uses arraycopy to combine all the byte arrays so they can be HMAC'd together using a Mac.
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] computeHash1() throws NoSuchAlgorithmException {
        //this needs to compute hash1 which is the clientpublickey, server public key, serverNonce, client nonce, and shared secret hashed
        //combine all the byte[]'s that I need to hash
        byte[] noncesCombined = new byte[serverNonce.length + clientNonce.length + sharedSecret.length + clientPubKey.getEncoded().length + serverPubKey.getEncoded().length];
        System.arraycopy(clientNonce,0, noncesCombined,0         , clientNonce.length);
        System.arraycopy(serverNonce,0, noncesCombined, clientNonce.length, serverNonce.length);
        System.arraycopy(sharedSecret,0, noncesCombined, (clientNonce.length + serverNonce.length), sharedSecret.length);
        int len1 = clientNonce.length + serverNonce.length + sharedSecret.length;
        System.arraycopy(clientPubKey.getEncoded(),0, noncesCombined, len1, clientPubKey.getEncoded().length);
        System.arraycopy(serverPubKey.getEncoded(),0, noncesCombined, (len1 + clientPubKey.getEncoded().length), serverPubKey.getEncoded().length);

        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "HmacSHA1"); //secretkeyspec takes a byte[], should I combine all my keys together and pass in?
        Mac mac = Mac.getInstance("HmacSHA1");
        try {
            mac.init(keySpec); //**
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] rawHmac = mac.doFinal(sharedSecret);
//        String result;
//        result = new Base64().encodeToString(rawHmac);
//                byte[] and 2 strings
        return rawHmac;
    }

    /**
     * Combines all the needed byte arrays with the arraycopy and uses the Mac to HMAC the bytes
     * @param hash1
     * @return
     */
    public static byte[] computeHash2(byte[] hash1){
        //this needs to hash the servers hash, clientpublickey, server public key, serverNonce, client nonce, and shared secret
        byte[] newHash = new byte[hash1.length + serverNonce.length + clientNonce.length + sharedSecret.length + clientPubKey.getEncoded().length + serverPubKey.getEncoded().length];
        //fill the byte array with all the parts mention above
        System.arraycopy(clientNonce,0, newHash,0         , clientNonce.length);
        System.arraycopy(serverNonce,0, newHash, clientNonce.length, serverNonce.length);
        System.arraycopy(sharedSecret,0, newHash, (clientNonce.length + serverNonce.length), sharedSecret.length);
        int len1 = clientNonce.length + serverNonce.length + sharedSecret.length;
        int len2 = clientPubKey.getEncoded().length + serverPubKey.getEncoded().length;
        System.arraycopy(clientPubKey.getEncoded(),0, newHash, len1, clientPubKey.getEncoded().length);
        System.arraycopy(serverPubKey.getEncoded(),0, newHash, (len1 + clientPubKey.getEncoded().length), serverPubKey.getEncoded().length);
        System.arraycopy(hash1, 0, newHash, (len1 + len2), hash1.length);

        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "HmacSHA1"); //secretkeyspec takes a byte[], should I combine all my keys together and pass in?
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            mac.init(keySpec); //**
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] rawHmac2 = mac.doFinal(sharedSecret);
        return rawHmac2;
    }

    /**
     * Method that takes a socket and a hash and sends via a DataOutputStream
     * @param socket
     * @param hash
     * @throws IOException
     */
    public static void sendHash(Socket socket, byte[] hash) throws IOException {
//        System.out.println("Starting sendHash");
        DataOutputStream hashOut = new DataOutputStream(socket.getOutputStream());
        hashOut.write(hash);
        hashOut.flush();
        OutputStream clientOut = socket.getOutputStream(); //probably can clean up by sending length of the hash then hash, then sending the length of the client, then client
        String client = "CLIENT";
        clientOut.write(client.getBytes());
        clientOut.flush();
//        System.out.println("Finishing sendHash");
    }

    /**
     * Creates 4 SecretKeys using a keygenerator and the sharedSecret as a seed
     */
    public static void create4Keys(){
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        random.setSeed(sharedSecret); // s is the master secret

        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("DESede");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(random);

        clientAuthKey = keyGenerator.generateKey();
        serverAuthKey = keyGenerator.generateKey();
        clientEncKey = keyGenerator.generateKey();
        serverEncKey = keyGenerator.generateKey();

        System.out.println("Mutual authentication completed - Secure Keys Successfully created.");
//        System.out.println(clientAuthKey);
//        System.out.println(clientAuthKey.getAlgorithm());
//        System.out.println(clientAuthKey.getEncoded());
//        System.out.println(toLong(serverAuthKey.getEncoded()));
    }

    /**
     * Uses the data input stream to read a file passed over the socket. The size is passed
     * with writeInt/readInt.
     * @param socket
     * @throws IOException
     */
    public static void readFile(Socket socket) throws IOException {
//        System.out.println("Starting readFile");
        DataInputStream fileIn = new DataInputStream(socket.getInputStream());
        int length = fileIn.readInt();                    // read length of incoming message
        byte[] serverFileIn = new byte[length];
        fileIn.readFully(serverFileIn);
        FileOutputStream file = new FileOutputStream("testFileFromServer");
        file.write(serverFileIn);
//        FileUtils.writeByteArrayToFile(new File("pathname"), myByteArray)
//        System.out.println("Finishing readFile");
    }

    /**
     * Same as readFile method above, but this uses a Cipher to decrypt the file with DESede
     * @param socket
     * @throws IOException
     * @throws InvalidKeyException
     */
    public static void readEncryptedFile(Socket socket) throws IOException, InvalidKeyException {
//        System.out.println("Starting readEncryptedFile");
        DataInputStream fileIn = new DataInputStream(socket.getInputStream());
        int length = fileIn.readInt();                    // read length of incoming message
        byte[] serverFileIn = new byte[length];
        fileIn.readFully(serverFileIn);

        Cipher decrypt = null;
        try {
            decrypt = Cipher.getInstance("DESede");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        decrypt.init(Cipher.DECRYPT_MODE, serverEncKey);
        byte[] decryptedMessage = null;
        try {
            decryptedMessage = decrypt.doFinal(serverFileIn);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        FileOutputStream file = new FileOutputStream("testEncryptedFileFromServer");
        file.write(decryptedMessage);
        System.out.println("Client has decrypted and saved file from server.");
//        FileUtils.writeByteArrayToFile(new File("pathname"), myByteArray)
//        System.out.println("Finishing readEncryptedFile");
    }

    /**
     * A private function to convert a byte array to a long for visual inspection of bytes sent to the server
     * @param byteArr
     * @return
     */
    private static long toLong(byte[] byteArr) {
        long value = 0;
        for (int i = 0; i < byteArr.length; i++) {
            value += ((long) byteArr[i] & 0xffL) << (8 * i);
        }
        return value;
    }
}
