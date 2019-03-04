package jar;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RequestHandlerThread extends Thread implements Runnable {

    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    private X509Certificate caCert;
    private PrivateKey caKey;

    private static final String REPOSITORY_IP;

    private static final int REPOSITORY_PORT;

    static {
        REPOSITORY_IP = Configuration.get("IP_REPOSITORY");
        REPOSITORY_PORT = Integer.parseInt(Configuration.get("PORT_REPOSITORY"));
    }

    public RequestHandlerThread(SSLSocket sslSocket, X509Certificate caCert, PrivateKey caKey) throws Exception {
        try {
            this.caCert = caCert;
            this.caKey = caKey;
            this.clientSslSocket = sslSocket;
            this.clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            this.clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
        } catch (IOException e) {
            String reason = "Failed to create data input/output stream";
            Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, reason, e);
            throw new Exception(e);
        }
    }

    @Override
    public void run() {
        try {
            byte[] requestData = readDataFromInputStream(clientDataInputStream);
            byte[] responseData;
            try {
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(requestData);

                System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CSR received from: " + csr.getSubject());
                // get addresses of CRL and OCSP Responder
                String CRL_URL = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP") + "/certificaterevocationlist.crl";
                String OCSP_URL = "http://" + Configuration.get("IP_VA") + ":" + Configuration.get("PORT_VA");
                // Create Certificate
                X509Certificate certificate = CSRManager.retrieveCertificateFromCSR(csr, caKey, caCert, CRL_URL, OCSP_URL);
                System.out.println("Certificate Created Successfully: " + certificate.getSubjectDN() + " : serialNumber=" + certificate.getSerialNumber());
                responseData = certificate.getEncoded();

                byte[] repositoryResponse = null;
                try {
                    System.out.println("Certificate " + certificate.getSerialNumber() + " Publication Request sent to : " + REPOSITORY_IP + ":" + REPOSITORY_PORT);
                    repositoryResponse = updateRemoteRepository(certificate.getEncoded());

                    if ("Success".equals(new String(repositoryResponse))) {
                        System.out.println(REPOSITORY_IP + ":" + REPOSITORY_PORT + ": Certificate Published Successfully...");
                    } else {
                        System.out.println(REPOSITORY_IP + ":" + REPOSITORY_PORT + ": Certificate Publication Failed...");
                        String response = "Could Not Create Certificate";
                        responseData = response.getBytes();
                    }
                } catch (Exception e) {
                    System.err.println("ERROR: Could Not Connect to " + REPOSITORY_IP + ":" + REPOSITORY_PORT + " CSR Cancelled");
                    String response = "Could Not Create Certificate";
                    responseData = response.getBytes();
                }

            } catch (Exception e) {
                String certSerialNumber = new String(requestData);
                System.out.println(clientSslSocket.getInetAddress().getHostAddress() +
                        ": Certificate Revocation Request for certificate no: " + certSerialNumber);
                try {
                    String crlFileName = Configuration.get("CRL_FILE_PATH");
                    X509CRLHolder crlHolder = CRLManager.readCRLFromFile(crlFileName);
                    X509CRLHolder updatedCrlHolder = CRLManager.revokeCertificate(crlHolder, certSerialNumber, caCert, caKey);

                    //save to the file system
                    File crlFile = new File(crlFileName);
                    FileUtils.writeByteArrayToFile(crlFile, updatedCrlHolder.getEncoded());

                    System.out.println("CRL (version " + crlHolder.getExtension(Extension.cRLNumber).getParsedValue().toString() +
                            ") Successfully Updated with new entry '" + certSerialNumber + "'");

                    System.out.println("CRL (version " + updatedCrlHolder.getExtension(Extension.cRLNumber).getParsedValue().toString() +
                            ") Publication Request sent to : " + REPOSITORY_IP + ":" + REPOSITORY_PORT);

                    String response = "Certificate no: " + certSerialNumber + " revoked Successfully";
                    responseData = response.getBytes();
                    byte[] repositoryResponse = updateRemoteRepository(updatedCrlHolder.getEncoded());

                    if ("Success".equals(new String(repositoryResponse))) {
                        System.out.println(REPOSITORY_IP + ":" + REPOSITORY_PORT + ": CRL Published Successfully...");
                    } else {
                        System.out.println(REPOSITORY_IP + ":" + REPOSITORY_PORT + ": CRL Publication Failed...");
                    }


                } catch (Exception ex) {
                    String response = "Could Not Publish the Revocation Status, Please expect delay...";
                    responseData = response.getBytes();
                }
            }

            if (requestData != null) {
                clientDataOutputStream.write(responseData);
                System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                System.out.println("--------------- END ------------------");
            }

        } catch (Exception ex) {
            Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException ex) {
                Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private byte[] updateRemoteRepository(byte[] data) throws IOException, CertificateEncodingException {
        System.setProperty("javax.net.ssl.keyStore", "keystore/ca.keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket connectionRepository = (SSLSocket) f.createSocket(REPOSITORY_IP, REPOSITORY_PORT);
        connectionRepository.startHandshake();
        DataOutputStream w = new DataOutputStream(connectionRepository.getOutputStream());
        DataInputStream r = new DataInputStream(connectionRepository.getInputStream());
        w.write(data);
        byte[] repositoryResponse = readDataFromInputStream(r);
        connectionRepository.close();
        return repositoryResponse;
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