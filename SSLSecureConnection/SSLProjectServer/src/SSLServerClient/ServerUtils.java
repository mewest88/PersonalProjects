package SSLServerClient;

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

public class ServerUtils {

    //public member variables
    public static PublicKey serverPubKey;
    public static PublicKey clientPubKey;
    public static PrivateKey serverPrivateKey;

    public static byte[] clientNonce;
    public static byte[] serverNonce;
    public static byte[] sharedSecret;

    public static SecretKey clientAuthKey;
    public static SecretKey serverAuthKey;
    public static SecretKey clientEncKey;
    public static SecretKey serverEncKey;

    /**
     * Opens up a certificate sent over the socket. I also pulls the public key from the cert.
     * @param socket
     * @throws IOException
     * @throws CertificateException
     */
    public static void openCertificate(Socket socket) throws IOException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(socket.getInputStream());
        clientPubKey = cert.getPublicKey();
//        System.out.println("client pub key = " + clientPubKey);
//        System.out.println("cert");
//        System.out.println(cert.toString());

    }

    /**
     * sends server cert and a nonce encrypted with client public key
     * send over the cert and flush the output stream and then send over the encrypted nonce
     * creates the cert using a certificate factory and sends it over the socket via an outputstream
     * @param socket
     * @throws IOException
     * @throws CertificateException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static void createCertificate(Socket socket) throws IOException, CertificateException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
//        System.out.println("Starting createCertificate");
        //grabs its own cert and sends it to the client
//        System.out.println("in server create cert");
        FileInputStream fis = new FileInputStream("sslCertSigned.cert");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(fis);
        serverPubKey = cert.getPublicKey();
        OutputStream outsCert = socket.getOutputStream();
        outsCert.write(cert.getEncoded());
        outsCert.flush();
//        System.out.println("finish create cert");
//        System.out.println("cert");
//        System.out.println(cert.toString());
        //create nonce
        generateNonce();
        BigInteger nonce = new BigInteger(serverNonce);
//        System.out.println("server nonce = " + nonce);
//        System.out.println("server nonce(long) = " + toLong(serverNonce));
//        DataOutputStream outsNonce = new DataOutputStream(socket.getOutputStream());
//        outsNonce.write(nonce);
//        outsNonce.flush();
        byte[] encryptedNonce = encrypt(serverNonce);
//        BigInteger encryptedNonce = new BigInteger(serverNonce);
//        System.out.println("RSA encrypted nonce = " + encryptedNonce.toString());
        DataOutputStream outsNonce = new DataOutputStream(socket.getOutputStream());
//        outsNonce.writeInt(serverNonce.length);
        outsNonce.write(encryptedNonce);
        outsNonce.flush();
        System.out.println("Finishing createCertificate - cert and nonce sent");
    }

    /**
     * generates a random nonce 8 bytes large using a SecureRandom generator
     */
    public static void generateNonce(){
//        System.out.println("Starting generateNonce");
        SecureRandom rand = new SecureRandom();
        serverNonce = new byte[8];
        rand.nextBytes(serverNonce);
//        BigInteger bigIntNonce = new BigInteger(nonce);
//        System.out.println("nonce (big int version) = " + bigIntNonce);
//        return bigIntNonce;
//        System.out.println("Finishing generateNonce");
    }

    /**
     * Creates a cipher and encrypts a byte array passed through
     * this is used specifically to encrypt the nonce in the handshake
     * @param nonce
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        System.out.println("Starting encrypt");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
        byte[] encryptedNonce = cipher.doFinal(nonce);
        BigInteger bigIntNonce = new BigInteger(encryptedNonce);
//        System.out.println("server encrypted nonce(big int) = " + bigIntNonce);
//        System.out.println("server encrypted nonce(long) = " + toLong(encryptedNonce));
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
        //read in the data sent over from the client
        DataInputStream encryptedNonceIn = new DataInputStream(socket.getInputStream());
        byte[] encryptedClientNonce = new byte[256];
//        int length = encryptedNonceIn.readInt();                    // read length of incoming message
        encryptedNonceIn.readFully(encryptedClientNonce); // read the nonce
//        encryptedNonceIn.close();
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
            cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey); //**
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] decryptedClientNonce = null;
        try {
            decryptedClientNonce = cipher.doFinal(encryptedClientNonce); //**
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        clientNonce = decryptedClientNonce;
//        System.out.println("clients decrypted nonce = " + clientNonce.toString());
//        System.out.println("clients decrypted nonce = " + toLong(clientNonce));
//        }
//        System.out.println("Finishing decrypt");
    }

    /**
     * Uses a FileInputStream and a KeyFactory to read in and pull the private key from the .der file
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static void extractPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //get the private key from the server cert
//        System.out.println("Starting extractPrivateKey");
        File clientPrivKey = new File("prv.der");
        FileInputStream fis = null;
        fis = new FileInputStream(clientPrivKey);
        byte[] privKeyArray = new byte[(int)clientPrivKey.length()];
        fis.read(privKeyArray);
        fis.close();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(privKeyArray);
        serverPrivateKey = kf.generatePrivate(key);
//        System.out.println("Finishing extractPrivateKey");
    }

    /**
     * loops through the serverNonce and the clientNonce to create the shared secret using the XOR
     */
    public static void createSharedSecret() {
        sharedSecret = new byte[serverNonce.length];
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
        byte[] serverHash2 = computeHash2(computeHash1()); //create the clients hash
        DataInputStream clientHash2In = new DataInputStream(socket.getInputStream());
        byte[] clientHash2 = new byte[serverHash2.length];
        clientHash2In.readFully(clientHash2); // read the nonce
        assert serverHash2.length != clientHash2.length; //not the best use as this is error checking
//        if(serverHash2.length == clientHash2.length) {
//            System.out.println("The hashes are the same length!");
//        }
//        assert clientHash1 != clientHash2; //not the best use as this is error checking
        if(Arrays.equals(serverHash2, clientHash2)){
            System.out.println("The hashes are the same!");
        } else {
            System.out.println("The hashes are different");
            System.exit(-1);
        }
//        System.out.println("hash lengths: " + serverHash2.length);
////        System.out.println("client hash: " + serverHash2.toString());
////        System.out.println("server hash: " + clientHash2.toString());
////        System.out.println("client hash: " + toLong(serverHash2));
////        System.out.println("server hash: " + toLong(clientHash2));
////        BigInteger clientBIH = new BigInteger(serverHash2);
////        BigInteger serverBIH = new BigInteger(clientHash2);
////        System.out.println("client hash(BI): " + clientBIH);
////        System.out.println("server hash(BI): " + serverBIH);
        DataInputStream clientStringIn = new DataInputStream(socket.getInputStream());
        byte[] s = "CLIENT".getBytes();
        byte[] clientString = new byte[s.length];
        clientStringIn.readFully(clientString); // read the nonce
        String CLIENT = new String(clientString);
//        if(CLIENT != "CLIENT") {
//            System.out.println("CLIENT not passed");
//            System.exit(-1);
//        }
//        System.out.println("should say CLIENT: " + CLIENT);
        System.out.println("The hashes have been compared and are correct.");
    }

    /**
     * Uses arraycopy to combine all the byte arrays so they can be HMAC'd together using a Mac.
     * @return rawHmac byte[]
     * @throws NoSuchAlgorithmException
     */
    public static byte[] computeHash1() throws NoSuchAlgorithmException {
//        System.out.println("Starting computeHash1");
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
        Mac mac = Mac.getInstance("HmacSHA1");//HmacSHA1
        try {
            mac.init(keySpec); //**
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] rawHmac = mac.doFinal(sharedSecret);
//        String result;
//        result = new Base64().encodeToString(rawHmac);
//                byte[] and 2 strings
//        System.out.println("Finishing computeHash1");
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
        OutputStream serverOut = socket.getOutputStream(); //probably can clean up by sending length of the hash then hash, then sending the length of the client, then client
        String server = "SERVER";
        serverOut.write(server.getBytes());
        serverOut.flush();
//        System.out.println("Finishing generateNonce");
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
     * Uses a data output stream to send an unencrypted file over the socket
     * @param socket
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static void sendFile(Socket socket) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        DataOutputStream fileOver = new DataOutputStream(socket.getOutputStream());
        File file = new File("51kbFileTest.txt");
        FileInputStream fis = new FileInputStream(file);
        byte[] fileToSend = new byte[(int)file.length()];
//        System.out.println("file length = " + fileToSend.length);
        fis.read(fileToSend);
        fileOver.writeInt(fileToSend.length);
        fileOver.write(fileToSend);
        fileOver.flush();
    }

    /**
     * Same as sendFile method above, but this uses a Cipher to encrypt the file with DESede
     * @param socket
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static void sendEncryptedFile(Socket socket) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        DataOutputStream fileOver = new DataOutputStream(socket.getOutputStream());
        File file = new File("51kbFileTest.txt");
        FileInputStream fis = new FileInputStream(file);
        byte[] fileToSend = new byte[(int)file.length()];
        fis.read(fileToSend);

        Cipher encrypted = Cipher.getInstance("DESede");
        encrypted.init(Cipher.ENCRYPT_MODE, serverEncKey);
        byte[] encryptedMessage = null;
        try {
            encryptedMessage = encrypted.doFinal(fileToSend);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
//        System.out.println("encrypted file length = " + fileToSend.length);
        fileOver.writeInt(encryptedMessage.length);
        fileOver.write(encryptedMessage);
        fileOver.flush();
        System.out.println("Server has sent file.");
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
