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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

class Client {

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


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

        if (args.length != 3) {
            System.out.println("Usage: java Client <server hostname> <port number> <userID>");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);

        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        ) {

            String userId = args[2];
            String hashedUserId = getHash(userId);
            out.println(hashedUserId);
            out.println(userId);

            File g = new File("server.pub"); // Reading the server's public key named as "server.pub".
            if(!g.exists()) {
                System.err.println("Server's public key not found. Exiting...");
                System.exit(1); // Exiting as server's public key is not found
            }
            byte[] gkeyBytes = Files.readAllBytes(g.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(gkeyBytes);
            KeyFactory gkf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = gkf.generatePublic(pubSpec);

            boolean hasMessages = Boolean.parseBoolean(in.readLine()); // Checking if the user has any messages

            File f = new File(userId + ".prv"); // Reading the user's private key assuming it is named as <userId>.prv
            if(!f.exists()) {
                System.err.println("Private key not found. Exiting... (Generate keypairs before running client)");
                System.exit(1); // Exiting as private key is not found
            }
            byte[] fkeyBytes = Files.readAllBytes(f.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(fkeyBytes);
            KeyFactory fkf = KeyFactory.getInstance("RSA");
            PrivateKey prvKey = fkf.generatePrivate(prvSpec);


            if (hasMessages) {
                System.out.println("You have new messages -> ");
                String message = "";

                //verification and displaying of each message the user has received
                while (!(message = in.readLine()).equals("No more messages")) {
                    String signatureStr = in.readLine();
                    byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
                    boolean b = verifySignature(message.getBytes(), signatureBytes, pubKey); //verification
                    //System.out.println(b); Just to print the Verified Signature.
                    if(b) {
                        byte[] encryptedMessageBytes = Base64.getDecoder().decode(message);
                        String decryptedMessage = decrypt(encryptedMessageBytes, prvKey); //decryption

                        String[] parts = decryptedMessage.split("\\|");     //separating timestamp and message from the decrypted message
                        String messagecontent = parts[0];
                        String timestamp = parts[1];

                        System.out.println("Date: " + timestamp);
                        System.out.println("Message: " + messagecontent);


                    }else {
                        System.err.println("Signature verification failed.");
                        System.exit(1); // Exiting as signature verification failed
                    }
                }
            } else {
                System.out.println("No new messages for you."); // Shows if the user has no messages
            }

            // Message sending part
            System.out.print("Do you want to send a message to another user? (yes/no): ");
            String sendMsg = userInput.readLine();

            // Validating user input for 'yes' or 'no'
            while (!sendMsg.equalsIgnoreCase("yes") && !sendMsg.equalsIgnoreCase("no")) {
                System.out.print("Invalid input. Please enter 'yes' or 'no':");
                sendMsg = userInput.readLine();
            }

            if ("yes".equalsIgnoreCase(sendMsg)) {
                System.out.print("Enter receiver's ID: "); // Enter receiver's ID
                String recId = userInput.readLine();
                System.out.print("Enter your message: "); // Enter message
                String msg = userInput.readLine();

                // Generate current date and time
                LocalDateTime current = LocalDateTime.now();
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("E MMM dd HH:mm:ss 'GMT' yyyy");
                String formattedDateTime = current.format(formatter);

                // Prepend the receiver's ID, timestamp to the message

                String messagecontent = recId +  "|" + formattedDateTime + "|" + msg;

                String encryptedMessage = encrypt(messagecontent, pubKey); // Encryption of message
                byte[] signedDoc = sign(encryptedMessage.getBytes("UTF-8"), prvKey); // Signature of message

                out.println(Base64.getEncoder().encodeToString(signedDoc));
                out.println(encryptedMessage);

                System.out.println("Message sent.");

            } else {
                System.out.println("No message sent.");
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}