package jar;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import static jar.Client.readUserInput;


/**
 * Created by Suavek on 03/03/2017.
 */
public class CertificateManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Method generates PKC10 CSR based on subject name and the key pair
     * then it connects to remote server (CA or RA) to acquire signed cert based on the generated CSR
     *
     * @param caIP
     * @param caPort
     * @param userCredentials
     * @param keyPair
     * @return
     */
    public static X509Certificate requestCertificate(String caIP, int caPort, String userCredentials, KeyPair keyPair) {
        X509Certificate cert = null;
        try {

            String subjectName = userCredentials.split(":")[0];
            PKCS10CertificationRequest csr = CSRManager.generateCSR(subjectName, keyPair);
            cert = new RAConnectionHandler(caIP, caPort).requestCertificate(csr, userCredentials);
        } catch (Exception e) {
            String message = (e.getMessage() != null) ? e.getMessage() : "";
            System.err.println("Certification Request Failed ! " + message + "\n");
        }
        return cert;
    }

    /**
     * Method connects to RA server in order to revoke the certificate
     *
     * @param caIP
     * @param caPort
     * @param userCredentials
     */
    public static String revokeCertificate(String caIP, int caPort, String userCredentials) {
        try {
            return new RAConnectionHandler(caIP, caPort).revokeCertificate(userCredentials);
        } catch (Exception e) {
            System.err.println("Certification Revocation Failed !");
        }
        return null;
    }

    public static void validateMyCertificate(X509Certificate userCert, X509Certificate issuerCert, X509Certificate ocspResponderCert) {
        try {
            System.out.println("Select Option:\n1 - CRL\n2 - OCSP\n3 - <--- Back");
            System.out.print("Choice:");
            Integer operationType = readUserInput();
            System.out.println("");
            if (operationType != null && (operationType >= 1 && operationType <= 2)) {
                if (operationType == 1) {
                    boolean isValidCRL = PathChecking.checkPathUserCertificate(userCert, true, null, new X509Certificate[]{}, issuerCert);
                } else {
                    boolean isValidOSCP = PathChecking.checkPathUserCertificate(userCert, false, new PathCheckerOCSP(issuerCert, ocspResponderCert), new X509Certificate[]{}, issuerCert);
                }
            }


        } catch (Exception e) {
            System.out.println("Cannot retrieve certificate from your KeyStore " + e);
        }
    }

}
