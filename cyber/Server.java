import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import java.nio.file.*;

class Server {

    // Static map to store messages
    private static Map<String, List<String>> messages = new HashMap<>();

    /**
     * Append a prefix "gfhk2024:" to userId and Generates a MD5 hash of userId
     *
     * @param userId
     * @return hexadecimal string of userID
     *
     * */
    public static String getHash(String userId) {
        try {
            userId = "gfhk2024:" + userId;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(userId.getBytes());
            BigInteger x = new BigInteger(1, messageDigest);
            String hash = x.toString(16);

            while (hash.length() < 32) {
                hash = "0" + hash;
            }
            return hash;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Signatures a message using SHA256withRSA
     *
     * @param message and private key
     * @return signature
     *
     * */
    public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    /**
     * Verifies the signature of a message using SHA256withRSA
     *
     * @param message , signature and corresponding public key
     * @return true (verified) /false (failed verification)
     *
     * */
    public static boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initVerify(publicKey);
        signer.update(message);
        return signer.verify(signature);
    }

    /**
     *
     * Decryption of encrypted input using RSA/ECB/PKCS1Padding
     *
     * @param input and private key
     * @return decrypted string
     *
     * */
    public static String decrypt(byte[] input, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(input);
        return new String(decryptedBytes, "UTF-8");
    }

    /**
     * Encryption of input using RSA/ECB/PKCS1Padding
     *
     * @param inputString and public key
     * @return encrypted string
     *
     * */
    public static String encrypt(String inputString, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(inputString.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java Server <port>");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New connection established.");
                new ServerThread(socket).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ServerThread extends Thread {

        private Socket socket;

        public ServerThread(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try (
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
            ) {
                String hashedUserId = in.readLine();
                System.out.println("Sender hashed user ID: " + hashedUserId); // Printing the hashed user ID


                String userId = in.readLine();
                System.out.println("Sender user ID: " + userId); // Printing the unhashed user ID

                File h = new File(userId + ".pub"); // Reading the receiver's public key assuming it is named as <userID>.pub
                if(!h.exists()) {
                    System.err.println("Receiver's public key not found."); //printing error message if receiver's public key is not found
                    return;
                }
                byte[] hkeyBytes = Files.readAllBytes(h.toPath());
                X509EncodedKeySpec hpubSpec = new X509EncodedKeySpec(hkeyBytes);
                KeyFactory hkf = KeyFactory.getInstance("RSA");
                PublicKey hpubKey = hkf.generatePublic(hpubSpec);


                File f = new File("server.prv"); // Reading the server's private key assuming it is named as "server.prv"
                if(!f.exists()) {
                    System.err.println("Server's private key not found."); // printing error message if server's private key is not found
                    return;
                }
                byte[] fkeyBytes = Files.readAllBytes(f.toPath());
                PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(fkeyBytes);
                KeyFactory fkf = KeyFactory.getInstance("RSA");
                PrivateKey prvKey = fkf.generatePrivate(prvSpec);

                List<String> userMessages = messages.getOrDefault(hashedUserId, new ArrayList<>()); // Get user's messages from messages map according to hashed user ID

                if (!userMessages.isEmpty()) {
                    out.println(true); // Indicate that there are messages
                    for (String message : userMessages) {
                        String forsignature = message.toString();
                        byte[] serversignature = sign(forsignature.getBytes("UTF-8"), prvKey); // Signature of message
                        out.println(message); // Send message to client
                        out.println(Base64.getEncoder().encodeToString(serversignature)); // Send signature to client
                    }
                    out.println("No more messages"); // Indicate end of messages
                    messages.remove(hashedUserId); // Remove messages and ID after sending it to receiver
                } else {
                    out.println(false); // Indicate that there are no messages
                }

                String signatureStr = in.readLine(); // Receive signature from client

                if (signatureStr == null) {
                    System.out.println("No content received. User exited without sending any messages."); // No content received
                    return;
                }

                byte[] signature = Base64.getDecoder().decode(signatureStr);

                String encryptedMessage = in.readLine(); // Receive encrypted message from client
                if (encryptedMessage == null) {
                    System.err.println("Encrypted message is null.");
                    return;
                }

                boolean b = verifySignature(encryptedMessage.getBytes(), signature, hpubKey); // Verify signature

                System.out.println("Signature Verification Status:" + b); // Print verification status

                //If signature verification is successful then decrypt the message
                if(b){
                    byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
                    String decryptedMessage = decrypt(encryptedMessageBytes, prvKey); // Decrypt message

                    String receiverId = "";
                    String msgcontentwithouttimestamp = "";
                    String timestamp = "";
                    while (decryptedMessage != null) {
                        String[] parts = decryptedMessage.split("\\|"); // separating the receiver ID, TimeStamp and the Message Content.
                        receiverId = parts[0];
                        timestamp = parts[1];
                        msgcontentwithouttimestamp = parts[2];
                        break;
                    }


                    System.out.println("Receiver ID : " + receiverId); // Print receiver ID
                    System.out.println("Date: " + timestamp); // Print timestamp
                    System.out.println("Message: " + msgcontentwithouttimestamp); // Print message
                    //separating timestamp and message from the decrypted message
                    String msgcontent = msgcontentwithouttimestamp + "|" + timestamp;

                    File g = new File(receiverId + ".pub"); // Reading the receiver's public key assuming it is named as <receiverID>.pub
                    if(!g.exists()) {
                        System.err.println("Receiver's public key not found.");
                        return;
                    }
                    byte[] gkeyBytes = Files.readAllBytes(g.toPath());
                    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(gkeyBytes);
                    KeyFactory gkf = KeyFactory.getInstance("RSA");
                    PublicKey pubKey = gkf.generatePublic(pubSpec);

                    String ReEncryptedMessage = encrypt(msgcontent, pubKey); // Re-encrypt the Decrypted message with receiver's public key

                    String hashedReceiverId = getHash(receiverId); // Get hashed receiver ID
                    System.out.println("hash of receiver : " + hashedReceiverId);
                    // Add the re-encrypted message to the receiver's messages list
                    List<String> receiverMessages = messages.getOrDefault(hashedReceiverId, new ArrayList<>());
                    receiverMessages.add(ReEncryptedMessage);
                    messages.put(hashedReceiverId, receiverMessages);


                } else {
                    System.err.println("Signature verification failed.");
                }


            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}