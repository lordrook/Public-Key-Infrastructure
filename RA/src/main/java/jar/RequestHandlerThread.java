package jar;


import org.apache.commons.io.IOUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;

public class RequestHandlerThread extends Thread implements Runnable {

    DataInputStream clientDataInputStream;
    DataOutputStream clientDataOutputStream;
    SSLSocket clientSslSocket;

    private static final String CA_IP;
    private static final int CA_PORT;

    static {
        CA_IP = Configuration.get("IP_CA");
        CA_PORT = Integer.parseInt(Configuration.get("PORT_CA"));
    }

    public RequestHandlerThread(SSLSocket sslsocket) {
        this.clientSslSocket = sslsocket;
    }

    @Override
    public void run() {
        try {
            clientDataInputStream = new DataInputStream(clientSslSocket.getInputStream());
            clientDataOutputStream = new DataOutputStream(clientSslSocket.getOutputStream());
            byte[] credentialsData = readDataFromInputStream(clientDataInputStream);
            byte[] requestData;
            // check if requesting entity provided valid user credentials
            if (!AuthenticationHandler.verifyUserCredentials(credentialsData)) {
                clientDataOutputStream.write("Access Denied".getBytes());
                clientDataInputStream.close();
                System.out.println("Unauthorised User! Connection Terminated...");
                System.out.println("--------------- END ------------------");
                throw new Exception("Invalid Credentials");
            } else {
                clientDataOutputStream.write("Access Granted".getBytes());
            }

            String subject = new String(credentialsData).split(":")[0];
            String userPassword = new String(credentialsData).split(":")[1];
            X509Certificate userCertificate = getX509CertificateFromRepository(subject);

            try {
                // After successful verification of the credentials wait for the request data
                requestData = readDataFromInputStream(clientDataInputStream);
                // try to parse the request data to csr
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(requestData);
                String requestedSubjectName = csr.getSubject().toString();

                if (userCertificate != null) {
                    String certURL = "http://" + Configuration.get("IP_REPOSITORY") + ":"
                            + Configuration.get("PORT_REPOSITORY_HTTP") + "/get?" +
                            userCertificate.getSubjectDN().getName();
                    String response = "CSR Failed - certificate already exists! Please revoke or download it from: " + certURL;
                    clientDataOutputStream.write(response.getBytes());
                    clientDataInputStream.close();
                    System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CSR received from user : '" +
                            subject + "' : Request Denied! Certificate Already Exist...");
                    System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                    System.out.println("--------------- END ------------------");
                    return;

                } else {
                    if (!requestedSubjectName.equals("CN=" + subject)) {
                        String response = "Provided certificate Subject Name : " + requestedSubjectName +
                                "does not match with existing registration record :" + subject;
                        clientDataOutputStream.write(response.getBytes());
                        clientDataInputStream.close();
                        System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CSR received from user : '" +
                                subject + "' : Request Denied! Invalid CSR data...");
                        System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                        System.out.println("--------------- END ------------------");
                        return;
                    }
                    System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": CSR received from user : '" +
                            subject + "' : Request Accepted...");
                    System.out.println("Forwarding User Request To: " + "Root Certificate Authority : " + CA_IP + ":" + CA_PORT);
                }
            } catch (Exception e) {
                if (userCertificate != null) {
                    String certSerialNumber = userCertificate.getSerialNumber().toString();
                    requestData = certSerialNumber.getBytes();

                    String response = "Please confirm your password : ";
                    clientDataOutputStream.write(response.getBytes());

                    String confirmPassword = new String(readDataFromInputStream(clientDataInputStream));

                    if (!userPassword.equals(confirmPassword)) {
                        response = "Provided password is invalid";
                        clientDataOutputStream.write(response.getBytes());
                        clientDataOutputStream.close();
                        System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": Certificate Revocation Request from user: '" +
                                subject + "' : Request Denied! Additional Authentication Failed...");
                        System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                        System.out.println("--------------- END ------------------");
                        return;
                    }
                    System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": Certificate Revocation Request from user: '" +
                            subject + "' for certificate number : " + certSerialNumber + "' : Request Accepted...");
                    System.out.println("Certificate: '" + certSerialNumber + "' Revocation Request sent to : " + CA_IP + ":" + CA_PORT);

                } else {
                    String response = "There is no record on certificate for : " + subject;
                    clientDataOutputStream.write(response.getBytes());
                    clientDataInputStream.close();
                    System.out.println(clientSslSocket.getInetAddress().getHostAddress() + ": Certificate Revocation Request from user: '" +
                            subject + "' : Request Denied! Certificate Does Not Exists...");
                    System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
                    System.out.println("--------------- END ------------------");
                    return;
                }
            }

            String keyStorePath = Configuration.get("RA_KS_PATH");
            String keyStorePassword = Configuration.get("RA_KS_PASS");

            System.setProperty("javax.net.ssl.keyStore", keyStorePath);
            System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket c = (SSLSocket) f.createSocket(CA_IP, CA_PORT);
            c.startHandshake();
            DataOutputStream w = new DataOutputStream(c.getOutputStream());
            DataInputStream r = new DataInputStream(c.getInputStream());

            w.write(requestData);
            byte[] caResponse = readDataFromInputStream(r);
            c.close();

            try {
                X509Certificate cert = CertificateUtils.certificateFromByteArray(caResponse);
                System.out.println(CA_IP + ":" + CA_PORT + ": Certificate no: " + cert.getSerialNumber() + " created successfully...");
            } catch (Exception e) {
                System.out.println(CA_IP + ":" + CA_PORT + ": " + new String(caResponse));
            }


            clientDataOutputStream.write(caResponse);
            System.out.println("Response sent to : " + clientSslSocket.getInetAddress().getHostAddress());
            System.out.println("--------------- END ------------------");

        } catch (Exception ex) {
            //Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        } finally {
            try {
                this.clientSslSocket.close();
            } catch (IOException ex) {
                //Logger.getLogger(RequestHandlerThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private X509Certificate getX509CertificateFromRepository(String s) throws IOException {
        String subjectName = s;
        String httpRepositoryURL = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP") + "/get?CN=";
        URL oracle = new URL(httpRepositoryURL + subjectName);
        byte[] bytes = IOUtils.toByteArray(oracle.openStream());
        return CertificateUtils.certificateFromByteArray(bytes);
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