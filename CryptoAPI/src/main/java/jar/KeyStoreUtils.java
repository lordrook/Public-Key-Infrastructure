package jar;

import com.google.common.io.Files;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by Suavek on 06/02/2017.
 */
public class KeyStoreUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyStore getKeyStore(String path, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, OperatorCreationException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        File keyStoreFile = new File(path);
        // If KeyStore does not exist create a new one
        if (!keyStoreFile.exists()) {
            createKeyStore(keyStore, keyStoreFile, path, password);
        } else {
            keyStore.load(new FileInputStream(path), password.toCharArray());
        }
        return keyStore;
    }


    private static void createKeyStore(KeyStore keyStore, File keyStoreFile, String path, String password) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, OperatorCreationException {
        Files.createParentDirs(keyStoreFile); // create parent directory tree
        keyStore.load(null); // Initialise empty keystore
        saveKeyStore(keyStore, path, password);
    }

    public static void saveKeyStore(KeyStore keyStore, String path, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, OperatorCreationException {
        keyStore.store(new FileOutputStream(path), password.toCharArray());
    }


    public static void setCertificateEntry(String certificateAlias, X509Certificate certificate, String path, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        KeyStore keyStore = getKeyStore(path, password);
        keyStore.setCertificateEntry(certificateAlias, certificate);
        saveKeyStore(keyStore, path, password);
    }

    public static void setKeyEntry(String kAlias, PrivateKey kPrivate, X509Certificate cert, String path, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, OperatorCreationException {
        KeyStore keyStore = getKeyStore(path, password);
        keyStore.setKeyEntry(kAlias, kPrivate, password.toCharArray(), new Certificate[]{cert});
        saveKeyStore(keyStore, path, password);
    }

    public static X509Certificate getCertificate(String certAlias, String path, String password) throws Exception {
        try {
            return (X509Certificate) getKeyStore(path, password).getCertificate(certAlias);
        } catch (Exception e) {
            throw new Exception("Could not retrieve certificate from the key store");
        }
    }

    public static PrivateKey getSecretKey(String keyAlias, String path, String password) throws Exception {
        try {
            return (PrivateKey) getKeyStore(path, password).getKey(keyAlias, password.toCharArray());
        } catch (Exception e) {
            throw new Exception("Could not retrieve secret key from the key store");
        }
    }
}
