package jar;

/**
 * Created by Suavek on 07/02/2017.
 */

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class VAServer {

    private SSLServerSocket sslServerSocket;
    private X509Certificate vaCert;
    private PrivateKey vaKey;

    public VAServer(SSLServerSocket sslServerSocket) {

        this.sslServerSocket = sslServerSocket;
        String vaKeyStorePath = Configuration.get("VA_KS_PATH");
        String vaKeyStorePassword = Configuration.get("VA_KS_PASS");
        String vaCertificateAlias = Configuration.get("VA_KS_ALIAS_CERT");
        String vaKeyAlias = Configuration.get("VA_KS_ALIAS_KEY");
        try {
            this.vaKey = KeyStoreUtils.getSecretKey(vaKeyAlias, vaKeyStorePath, vaKeyStorePassword);
            this.vaCert = KeyStoreUtils.getCertificate(vaCertificateAlias, vaKeyStorePath, vaKeyStorePassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while (true) {
            try {
                SSLSocket clientSslSocket = (SSLSocket) this.sslServerSocket.accept();
                System.out.println("-------------- BEGIN -----------------");
                System.out.println("New OCSP Request   : " + clientSslSocket.getInetAddress().getHostAddress());
                new RequestHandlerThread(clientSslSocket, this.vaCert, this.vaKey).start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {

        String keyPassword = Configuration.get("VA_KS_PASS");
        int portNo = Integer.parseInt(Configuration.get("PORT_VA"));

        try {
            String caKeyStorePath = Configuration.get("VA_KS_PATH");
            String caKeyStorePassword = Configuration.get("VA_KS_PASS");

            KeyStore keyStore = KeyStoreUtils.getKeyStore(caKeyStorePath, caKeyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(portNo);

            System.out.println("Starting VA Server...");
            new VAServer(sslServerSocket).run();
        } catch (Exception ex) {
            ex.printStackTrace();
            return;
        }
    }
}