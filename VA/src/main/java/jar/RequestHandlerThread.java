package jar;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RequestHandlerThread extends Thread implements Runnable {

    private SSLSocket clientSslSocket;
    private DataInputStream clientDataInputStream;
    private DataOutputStream clientDataOutputStream;
    private X509Certificate vaCert;
    private PrivateKey vaKey;

    public RequestHandlerThread(SSLSocket clientSslSocket, X509Certificate vaCert, PrivateKey vaKey) {
        try {
            this.clientSslSocket = clientSslSocket;
            this.clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            this.clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
            this.vaCert = vaCert;
            this.vaKey = vaKey;
        } catch (IOException e) {
            String reason = "Failed to create data input/output stream";
            Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, reason, e);
        }
    }

    @Override
    public void run() {
        try {
            byte[] requestData = readDataFromInputStream(clientDataInputStream);
            // Recreate the OCSPReq from the requestData
            OCSPReq ocspRequest = new OCSPReq(requestData);
            // retrieve latest crl from location specified in root certificate
            System.out.println("OCSP Request for : " + ocspRequest.getRequestList()[0].getCertID().getSerialNumber());
            X509CRLHolder crl = CRLManager.getCRLFromRepository(this.vaCert);
            OCSPResp ocspResponse = OCSPManager.generateOCSPResponse(ocspRequest, this.vaCert, this.vaKey, crl); //Generate the response
            clientDataOutputStream.write(ocspResponse.getEncoded());
            System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
            System.out.println("--------------- END ------------------");

        } catch (Exception e) {
            String msg = "Socket communication error";
            Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, msg, e);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException ex) {
                String msg = "Could not close client socket";
                Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, msg, ex);
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