package jar;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import static jar.Client.readUserInput;

/**
 * Created by Suavek on 24/03/2017.
 */
public class ChatConnection implements Runnable {

    private enum CHAT_MODE {
        SERVER, CLIENT;

        static CHAT_MODE getMode(int option) {
            if (option == 1) {
                return SERVER;
            } else if (option == 2) {
                return CLIENT;
            } else throw new IllegalArgumentException();
        }
    }

    private CHAT_MODE chatMode;

    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;
    SSLServerSocket sslServerSocket;
    SSLSocket sslSocket;
    SSLContext sslContext;
    X509Certificate myCert;
    Integer chatConnectionPortNumber;

    public ChatConnection(Integer option, String ksPath, String ksPass, X509Certificate myCert) throws Exception {
        // initialise fake trust store to be used in sslContext in order to be able
        // to retrieve peer certificates from ssl session without need for peer authentication
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }};
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStoreUtils.getKeyStore(ksPath, ksPass);
        kmf.init(ks, ksPass.toCharArray());
        this.sslContext = SSLContext.getInstance("SSL");
        this.sslContext.init(kmf.getKeyManagers(), trustAllCerts, new SecureRandom());
        this.chatMode = chatMode.getMode(option);
        this.myCert = myCert;
    }

    @Override
    public void run() {
        try {
            switch (this.chatMode) {
                case SERVER:
                    SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
                    System.out.print("Choose Port Number: ");
                    chatConnectionPortNumber = readUserInput();
                    SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(chatConnectionPortNumber);
                    ss.setNeedClientAuth(true);
                    try {
                        runChatServer(ss);
                    } catch (Exception e) {
                        System.out.println("~~ " + e.getMessage());
                        ss.close();
                    }
                    break;
                case CLIENT:
                    System.out.print("Enter the Host Name: ");
                    String hostName = new Scanner(System.in).nextLine();
                    System.out.print("Choose Port Number: ");
                    chatConnectionPortNumber = readUserInput();
                    SSLSocketFactory sf = sslContext.getSocketFactory();
                    SSLSocket s = (SSLSocket) sf.createSocket(hostName, chatConnectionPortNumber);

                    try {
                        runChatClient(s);
                    } catch (Exception e) {
                        System.out.println("~~ " + e.getMessage());
                        s.close();
                    }
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.err.println("Could Not Start Chat Session " + e.getMessage());
        }
    }


    private void runChatClient(SSLSocket ss) throws Exception {
        try {

            ss.startHandshake();

            SSLSession session = ss.getSession();
            X509Certificate peerCert = (X509Certificate) session.getPeerCertificates()[0];
            System.out.println("New Connection: " + peerCert.getSubjectDN().getName() + ", serialNumber=" + peerCert.getSerialNumber().toString());

            boolean isCertificateValid = validatePeerCertificate(peerCert);

            if (isCertificateValid == false) {
                System.out.println("WARNING! Received Certificate is NOT TRUSTED");
                System.out.println("Continue?\n1 - NO\n2 - YES\n");
                System.out.print("Choice:");
                Integer userChoice = readUserInput();
                if (userChoice != 2) {
                    ss.close();
                    return;
                }
            }

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(ss.getOutputStream()));
            BufferedReader reader = new BufferedReader(new InputStreamReader(ss.getInputStream()));
            System.out.println("");
            System.out.println("~~ Chat Session Started");
            chatInputOutputHandler(writer, reader, peerCert);

            writer.close();
            reader.close();
            System.out.println("Chat Session Ended");
        } catch (Exception e) {
            throw new Exception("Chat Session Ended");
        }
    }

    private void runChatServer(SSLServerSocket s) throws Exception {
        try {
            System.out.println("~~ Waiting For Connection...");
            SSLSocket c = (SSLSocket) s.accept();

            SSLSession session = c.getSession();
            X509Certificate peerCert = (X509Certificate) session.getPeerCertificates()[0];
            System.out.println("New Connection: " + peerCert.getSubjectDN().getName() + ", serialNumber=" + peerCert.getSerialNumber().toString());

            boolean isCertificateValid = validatePeerCertificate(peerCert);

            if (isCertificateValid == false) {
                System.out.println("WARNING! Received Certificate is NOT TRUSTED");
                System.out.println("Continue?\n1 - NO\n2 - YES\n");
                System.out.print("Choice:");
                Integer userChoice = readUserInput();
                if (userChoice != 2) {
                    c.close();
                    return;
                }
            }

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
            BufferedReader reader = new BufferedReader(new InputStreamReader(c.getInputStream()));

            String m = "~~ Connected";
            writer.write(m, 0, m.length());
            writer.newLine();
            writer.flush();
            System.out.println("");
            System.out.println("~~ Chat Session Started");
            chatInputOutputHandler(writer, reader, peerCert);

            writer.close();
            writer.close();
            c.close();
            s.close();

        } catch (Exception e) {
            throw new Exception("Chat Session Ended");
        }
    }

    private boolean validatePeerCertificate(X509Certificate cert) throws Exception {

        String ALIAS_CERT_CA = Configuration.get("CA_KS_ALIAS_CERT");
        String ALIAS_CERT_VA = Configuration.get("VA_KS_ALIAS_CERT");
        String TS_PATH_USER = Configuration.get("USER_TS_PATH");
        String TS_PASS_USER = Configuration.get("USER_TS_PASS");
        X509Certificate caRootCert = KeyStoreUtils.getCertificate(ALIAS_CERT_CA, TS_PATH_USER, TS_PASS_USER);
        X509Certificate vaCert = KeyStoreUtils.getCertificate(ALIAS_CERT_VA, TS_PATH_USER, TS_PASS_USER);

        try {
            return PathChecking.checkPathUserCertificate(cert, false, new PathCheckerOCSP(caRootCert, vaCert), new X509Certificate[]{}, caRootCert);
        } catch (Exception e) {
            return PathChecking.checkPathUserCertificate(cert, true, null, new X509Certificate[]{}, caRootCert);
        }
    }

    private void chatInputOutputHandler(BufferedWriter w, BufferedReader r, X509Certificate peerCert) throws IOException, InterruptedException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        PrintStream out = System.out;

        Runnable outputHandlerTask = () -> {
            String outMessage;
            try {
                String myAlias = CertificateUtils.getSubjectName(this.myCert) + ": ";
                while ((outMessage = in.readLine()) != null) {
                    w.write(outMessage, 0, outMessage.length());
                    w.newLine();
                    w.flush();
                }
            } catch (Exception e) {
                //System.out.println("~~ Remote Host Closed The Connection");
            }
        };

        Runnable inputHandlerTask = () -> {
            String inMessage;
            String peerAlias = CertificateUtils.getSubjectName(peerCert) + ": ";
            try {
                while ((inMessage = r.readLine()) != null) {
                    out.println(peerAlias + inMessage);
                }
            } catch (Exception e) {
                //System.out.println("~~ Remote Host Closed The Connection");
            }
        };

        Thread outputHandlerThread = new Thread(outputHandlerTask);
        Thread inputHandlerThread = new Thread(inputHandlerTask);
        outputHandlerThread.start();
        inputHandlerThread.start();
        while (outputHandlerThread.isAlive() && inputHandlerThread.isAlive()) {
        }
        outputHandlerThread.interrupt();
        inputHandlerThread.interrupt();
        outputHandlerThread.join(500);

        throw new IOException();
    }

}
