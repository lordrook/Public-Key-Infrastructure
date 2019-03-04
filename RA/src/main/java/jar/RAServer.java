package jar;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RAServer {
    private SSLServerSocket sslServerSocket;

    public RAServer(SSLServerSocket sslServerSocket) {
        this.sslServerSocket = sslServerSocket;
    }

    public void run() {
        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("-------------- BEGIN -----------------");
                System.out.println("New Request accepted from Client : " + sslSocket.getInetAddress().getHostAddress());
                new RequestHandlerThread(sslSocket).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {


        String trustKeyStorePath = Configuration.get("RA_TS_PATH");
        System.setProperty("javax.net.ssl.trustStore", trustKeyStorePath);

        try {
            String keyStorePath = Configuration.get("RA_KS_PATH");
            String keyStorePassword = Configuration.get("RA_KS_PASS");

            KeyStore keyStore = KeyStoreUtils.getKeyStore(keyStorePath, keyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            int portNo = Integer.parseInt(Configuration.get("PORT_RA"));
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(portNo);

            System.out.println("Starting RA Server...");
            new RAServer(sslServerSocket).run();
        } catch (Exception ex) {
            ex.printStackTrace();
            Logger.getLogger(RAServer.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }
    }
}
