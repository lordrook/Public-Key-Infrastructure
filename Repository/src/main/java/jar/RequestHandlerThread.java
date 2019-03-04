package jar;

import org.bouncycastle.cert.X509CRLHolder;

import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * Created by Suavek on 14/03/2017.
 */
public class RequestHandlerThread extends Thread implements Runnable {

    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    public RequestHandlerThread(SSLSocket sslsocket) throws IOException {
        this.clientSslSocket = sslsocket;
        clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
        clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
    }

    @Override
    public void run() {
        try {
            byte[] requestData = readDataFromInputStream(clientDataInputStream);

            try {
                X509CRLHolder crlNEW = new X509CRLHolder(requestData);
                System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CRL Update");
                if (CRLManager.isCRLValid(crlNEW, RepositoryUtils.getCertificate("CA_Certificate"))) {
                    RepositoryUtils.updateCRL(crlNEW);
                    clientDataOutputStream.write("Success".getBytes());
                    System.out.println("CRL Published Successfully...");
                } else {
                    clientDataOutputStream.write("Unauthorised".getBytes());
                }

            } catch (Exception e) {
                X509Certificate certificateToStore = CertificateUtils.certificateFromByteArray(requestData);
                String certAlias = CertificateUtils.getSubjectName(certificateToStore);
                System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": Publish Certificate");
                RepositoryUtils.setCertificateEntry(certAlias, certificateToStore);
                clientDataOutputStream.write("Success".getBytes());
            }

        } catch (Exception ex) {
            //Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                this.clientSslSocket.close();
                System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                System.out.println("--------------- END ------------------");
            } catch (IOException ex) {
                //Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }


    public byte[] readDataFromInputStream(DataInputStream dataInputStream) throws IOException {
        byte[] res = new byte[4096]; //Create an array big enough to does not be obliged to join all pieces.
        int read = dataInputStream.read(res); //Read in the socket and get back how many byte have been read
        if (read == -1) { //If nothing has been read raise an exception
            throw new IOException();
        }

        byte[] res_fitted = new byte[read]; //Now instantiate an array with the right size
        for (int i = 0; i < read; i++) { //Copy everything back into
            res_fitted[i] = res[i];
        }
        return res_fitted;
    }
}
