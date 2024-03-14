import java.io.*;
import java.security.*;

public class RSAKeyGen {

    public static void main(String [] args) throws Exception {

        if (args.length != 1) {
            System.err.println("Usage: java RSAKeyGen userid");
            System.exit(-1);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();

        FileOutputStream fos = new FileOutputStream(args[0] + ".pub");
        fos.write(kp.getPublic().getEncoded());
        fos.close();

        fos = new FileOutputStream(args[0] + ".prv");
        fos.write(kp.getPrivate().getEncoded());
        fos.close();

    }

}

