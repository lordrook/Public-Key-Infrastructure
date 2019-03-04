package jar;

import org.bouncycastle.operator.OperatorCreationException;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by Suavek on 14/03/2017.
 */
public class CRServer extends Thread implements Runnable {

    private SSLServerSocket sslServerSocket;

    public CRServer(SSLServerSocket sslServerSocket) {
        this.sslServerSocket = sslServerSocket;
    }

    public void run() {

        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("-------------- BEGIN -----------------");
                System.out.println("New Request accepted from CA : " + sslSocket.getInetAddress().getHostAddress());
                new RequestHandlerThread(sslSocket).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, IOException {

        String trustStorePath = Configuration.get("REPOSITORY_TS_PATH");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);

        try {
            String keyStorePath = Configuration.get("REPOSITORY_KS_PATH");
            String keyStorePassword = Configuration.get("REPOSITORY_KS_PASS");
            KeyStore keyStore = KeyStoreUtils.getKeyStore(keyStorePath, keyStorePassword);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            int portNo = Integer.parseInt(Configuration.get("PORT_REPOSITORY"));
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(portNo);
            sslServerSocket.setNeedClientAuth(true);

            System.out.println("Starting repository server...");
            new CRServer(sslServerSocket).start();
            System.out.println(">>>>> The service is running.");
        } catch (Exception e) {
            String msg = "Could not start repository server.";
            e.printStackTrace();
            Logger.getLogger(CRServer.class.getName()).log(Level.SEVERE, msg, e);
            return;
        }

        RepositoryUtils.initRepository();
        try {
            System.out.println("Starting repository Http server...");
            int portNumber = Integer.parseInt(Configuration.get("PORT_REPOSITORY_HTTP"));
            new CRHttpServer(portNumber); // jail current thread
        } catch (IOException e) {
            String msg = "Could not start repository Http server.";
            e.printStackTrace();
            Logger.getLogger(CRServer.class.getName()).log(Level.SEVERE, msg, e);
        }
    }
}
