package jar;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

/**
 * Created by Suavek on 06/03/2017.
 */
public class CryptoTools {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateKeyPair(Integer keySize) {
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(keySize);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return generator.generateKeyPair();
    }


}
