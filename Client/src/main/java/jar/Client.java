package jar;


import org.apache.commons.io.IOUtils;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Created by Suavek on 28/02/2017.
 */
public class Client {

    private static X509Certificate myCert;
    private static PrivateKey myKey;
    private static String RA_IP;
    private static int RA_PORT;

    private static String TS_PATH_USER;
    private static String TS_PASS_USER;

    private static String KS_PATH_USER;
    private static String KS_PASS_USER;
    private static String ALIAS_CERT_USER;
    private static String ALIAS_KEY_USER;

    private static String ALIAS_CERT_CA;
    private static String ALIAS_CERT_RA;
    private static String ALIAS_CERT_VA;

    private static Integer KEY_SIZE;

    public static void main(String... args) {

        RA_IP = Configuration.get("IP_RA");
        RA_PORT = Integer.parseInt(Configuration.get("PORT_RA"));

        ALIAS_CERT_CA = Configuration.get("CA_KS_ALIAS_CERT");
        ALIAS_CERT_RA = Configuration.get("RA_KS_ALIAS_CERT");
        ALIAS_CERT_VA = Configuration.get("VA_KS_ALIAS_CERT");

        TS_PATH_USER = Configuration.get("USER_TS_PATH");
        TS_PASS_USER = Configuration.get("USER_TS_PASS");
        System.setProperty("javax.net.ssl.trustStore", TS_PATH_USER);
        System.setProperty("javax.net.ssl.trustStorePassword", TS_PASS_USER);

        KS_PATH_USER = Configuration.get("USER_KS_PATH");
        KS_PASS_USER = Configuration.get("USER_KS_PASS");
        ALIAS_CERT_USER = Configuration.get("KS_ALIAS_CERT_USER");
        ALIAS_KEY_USER = Configuration.get("KS_ALIAS_KEY_USER");

        KEY_SIZE = Integer.parseInt(Configuration.get("USER_KEY_SIZE"));

        try {
            myCert = KeyStoreUtils.getCertificate(ALIAS_CERT_USER, KS_PATH_USER, KS_PASS_USER);
        } catch (Exception e) {

        }


        try {
            MenuHandler menuHandler = new MenuHandler();
            do {
                menuHandler.invoke();

            } while (true);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void userSelectionHandler(USER_CHOICE userChoice) throws Exception {
        switch (userChoice) {
            case SETUP_TRUST:
                try {
                    String repositoryAddress = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP") + "/";
                    String caC = "caroot.cer";
                    getCertificateFromRepository(repositoryAddress + caC, ALIAS_CERT_CA);
                    System.out.println(" ~~ CA Certificate Retrieved Successfully: " + repositoryAddress + caC);

                    String raC = "ra.cer";
                    getCertificateFromRepository(repositoryAddress + raC, ALIAS_CERT_RA);
                    System.out.println(" ~~ RA Certificate Retrieved Successfully: " + repositoryAddress + raC);

                    String vaC = "va.cer";
                    getCertificateFromRepository(repositoryAddress + vaC, ALIAS_CERT_VA);
                    System.out.println(" ~~ VA Certificate Retrieved Successfully: " + repositoryAddress + vaC);

                } catch (Exception e) {
                    System.err.println(" ~~ Could Not Retrieve Required Certificates!");
                }
                break;
            case REQUEST_CERTIFICATE:
                KeyPair keyPair = CryptoTools.generateKeyPair(KEY_SIZE);
                String userCredentials = ClientUtils.getUserCredentials();
                myCert = CertificateManager.requestCertificate(RA_IP, RA_PORT, userCredentials, keyPair);
                if (myCert != null) {
                    KeyStoreUtils.setCertificateEntry(ALIAS_CERT_USER, myCert, KS_PATH_USER, KS_PASS_USER);
                    KeyStoreUtils.setKeyEntry(ALIAS_KEY_USER, keyPair.getPrivate(), myCert, KS_PATH_USER, KS_PASS_USER);
                    CertificateUtils.saveCertToFile(myCert);
                }
                break;
            case VALIDATE_CERTIFICATE:
                myCert = KeyStoreUtils.getCertificate(ALIAS_CERT_USER, KS_PATH_USER, KS_PASS_USER);
                if (myCert == null) {
                    System.out.println("Error! You don't have a certificate, Please request a new one");
                    return;
                }
                X509Certificate caRootCert = KeyStoreUtils.getCertificate(ALIAS_CERT_CA, TS_PATH_USER, TS_PASS_USER);
                X509Certificate vaCert = KeyStoreUtils.getCertificate(ALIAS_CERT_VA, TS_PATH_USER, TS_PASS_USER);
                CertificateManager.validateMyCertificate(myCert, caRootCert, vaCert);
                break;

            case REVOKE_CERTIFICATE:
                revokeCertificate();
                break;
            case CHAT:
                System.out.println("~~~~~~~~ CHAT ~~~~~~~~");
                System.out.println("Select Option:\n1 - Server\n2 - Client\n3 - <--- Back");
                System.out.print("Choice: ");
                Integer operationType = readUserInput();
                System.out.println("");
                if (operationType != null && (operationType >= 1 && operationType <= 2)) {
                    try {
                        if (myCert == null) {
                            System.out.println("Error! You don't have certificate required for SSL Session");
                            return;
                        }

                        Runnable chat = new ChatConnection(operationType, KS_PATH_USER, KS_PASS_USER, myCert);
                        Thread chatSession = new Thread(chat);
                        try {
                            chatSession.start();
                            chatSession.join();
                        } catch (Exception e) {

                        }
                    } catch (Exception e) {
                        System.err.println("Could not start chat session : " + e.getMessage());
                    }
                }
                break;
            default:
        }
        System.out.println("");
    }

    private static void getCertificateFromRepository(String url, String alias) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        URL oracle = new URL(url);
        byte[] bytes = IOUtils.toByteArray(oracle.openStream());
        X509Certificate cert = CertificateUtils.certificateFromByteArray(bytes);
        KeyStoreUtils.setCertificateEntry(alias, cert, TS_PATH_USER, TS_PASS_USER);
    }

    private static void revokeCertificate() {
        String caIP = Configuration.get("IP_RA");
        int caPort = Integer.parseInt(Configuration.get("PORT_RA"));
        String userCredentials = ClientUtils.getUserCredentials();
        CertificateManager.revokeCertificate(caIP, caPort, userCredentials);
    }


    /**
     * Method reads user input for menu choice, if not an int then returns null
     *
     * @return int or null
     */
    public static Integer readUserInput() {
        Scanner sc = new Scanner(System.in);
        try {
            String s = sc.nextLine();
            return new Integer(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static class MenuHandler {

        public void invoke() throws Exception {
            Integer userChoice;
            System.out.println("~~~~~~ MAIN MENU ~~~~~~");
            System.out.println("Menu: ");
            System.out.println("1 - Certificate Management");
            System.out.println("2 - Chat Session");
            System.out.print("Choice: ");
            userChoice = readUserInput();
            System.out.println("");
            if (userChoice == null) {
                return;
            }
            if (userChoice == 1) {
                certManagement();
            } else if (userChoice == 2) {
                chatSession();
            }
            return;
        }

        private void chatSession() throws Exception {
            userSelectionHandler(USER_CHOICE.CHAT);
        }

        private void certManagement() throws Exception {
            Integer userChoice;
            System.out.println("~~~ CERT MANAGEMENT ~~~");
            System.out.println("Select Option: ");
            System.out.println("1 - Setup Trust");
            System.out.println("2 - Request Certificate");
            System.out.println("3 - Validate My Certificate");
            System.out.println("4 - Revoke My Certificate");
            System.out.println("5 - <---- Back");
            System.out.print("Choice: ");
            userChoice = readUserInput();
            System.out.println("");
            if (userChoice == null) {
                return;
            }
            userSelectionHandler(USER_CHOICE.getChoice(userChoice));
            return;
        }
    }

    public enum USER_CHOICE {
        SETUP_TRUST, REQUEST_CERTIFICATE, VALIDATE_CERTIFICATE, REVOKE_CERTIFICATE, CHAT, DEFAULT;

        static USER_CHOICE getChoice(int option) {
            if (option == 1) {
                return SETUP_TRUST;
            } else if (option == 2) {
                return REQUEST_CERTIFICATE;
            } else if (option == 3) {
                return VALIDATE_CERTIFICATE;
            } else if (option == 4) {
                return REVOKE_CERTIFICATE;
            } else {
                return DEFAULT;
            }
        }
    }
}
