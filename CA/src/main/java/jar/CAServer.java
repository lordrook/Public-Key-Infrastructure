package jar;


import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CAServer {

    private SSLServerSocket sslServerSocket;
    private X509Certificate caCert;
    private PrivateKey caKey;

    public CAServer(SSLServerSocket sslServerSocket) {

        this.sslServerSocket = sslServerSocket;
        String caKeyStorePath = Configuration.get("CA_KS_PATH");
        String caKeyStorePassword = Configuration.get("CA_KS_PASS");
        String caCertificateAlias = Configuration.get("CA_KS_ALIAS_CERT");
        String caKeyAlias = Configuration.get("CA_KS_ALIAS_KEY");
        try {
            this.caKey = KeyStoreUtils.getSecretKey(caKeyAlias, caKeyStorePath, caKeyStorePassword);
            this.caCert = KeyStoreUtils.getCertificate(caCertificateAlias, caKeyStorePath, caKeyStorePassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("-------------- BEGIN -----------------");
                System.out.println("New Request accepted from RA : " + sslSocket.getInetAddress().getHostAddress());
                new RequestHandlerThread(sslSocket, caCert, caKey).start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {


        String trustStorePath = Configuration.get("CA_TS_PATH");
        String keyPassword = Configuration.get("CA_TS_PASS");
        int portNo = Integer.parseInt(Configuration.get("PORT_CA"));

        System.setProperty("javax.net.ssl.trustStore", trustStorePath);

        try {
            String keyStorePath = Configuration.get("CA_KS_PATH");
            String keyStorePassword = Configuration.get("CA_KS_PASS");

            KeyStore keyStore = KeyStoreUtils.getKeyStore(keyStorePath, keyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(portNo);
            //sslServerSocket.setNeedClientAuth(true);
            System.out.println("Starting CA Server...");
            new CAServer(sslServerSocket).run();
        } catch (Exception ex) {
            ex.printStackTrace();
            return;
        }
    }
}
