package jar;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Scanner;


public class RAConnectionHandler {

    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;
    SSLSocket sslSocket;

    public RAConnectionHandler(String ip, int port) throws IOException {
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.sslSocket = (SSLSocket) sf.createSocket(ip, port);
        this.sslSocket.startHandshake();
        this.dataInputStream = new DataInputStream(sslSocket.getInputStream());
        this.dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
    }

    public X509Certificate requestCertificate(PKCS10CertificationRequest csr, String userCredentials) throws IOException {

        String remoteHostDetails = sslSocket.getInetAddress().getCanonicalHostName().toString() + ":" + sslSocket.getPort();

        byte[] response;
        byte[] bytesCSR = csr.getEncoded();
        //Write the user credentials
        dataOutputStream.write(userCredentials.getBytes());
        response = readDataFromInputStream(dataInputStream);
        System.out.println("~~ " + new String(response));

        //Attempt to write the CSR to the RA
        dataOutputStream.write(bytesCSR);
        response = readDataFromInputStream(dataInputStream);
        X509Certificate cert = null;
        try {


            System.out.println("CSR sent to " + remoteHostDetails);

            // Try to recreate the certificate from the byte[] received
            cert = CertificateUtils.certificateFromByteArray(response);
            System.out.println("Certificate " + cert.getSerialNumber() + " successfully retrieved from " + remoteHostDetails);

        } catch (Exception e) {
            System.err.println(remoteHostDetails + " : " + new String(response));
            System.out.println();
            //throw new IOException(new String(response));
        }
        return cert;

    }

    public String revokeCertificate(String userCredentials) throws IOException {
        byte[] response;
        //Write the user credentials
        dataOutputStream.write(userCredentials.getBytes());
        // authentication status
        response = readDataFromInputStream(dataInputStream);
        System.out.println("~~ " + new String(response));
        // send revocation request
        dataOutputStream.write("revoke".getBytes());
        // read response and display to the user
        String responseMessage = new String(readDataFromInputStream(dataInputStream));
        String remoteHostDetails = sslSocket.getInetAddress().getCanonicalHostName().toString() + ":" + sslSocket.getPort();
        System.out.println("Certificate Revocation Request sent to " + remoteHostDetails);
        System.out.println(remoteHostDetails + " : " + responseMessage);
        // read confirmation password from user
        dataOutputStream.write(new Scanner(System.in).nextLine().getBytes());
        // red response on revocation status
        responseMessage = new String(readDataFromInputStream(dataInputStream));

        System.out.println(remoteHostDetails + " : " + responseMessage);
        return responseMessage;
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