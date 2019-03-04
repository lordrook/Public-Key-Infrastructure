package jar;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;


public class PathCheckerOCSP extends PKIXCertPathChecker {
    private X509Certificate ocspResponderCert;
    private String ocspIP;
    private int ocspPort;

    public PathCheckerOCSP(X509Certificate issuerCert, X509Certificate ocspResponderCert) {
        this.ocspResponderCert = ocspResponderCert;
        String ocspResponderURL = CertificateUtils.ocspURLFromCert(issuerCert); // Get the address of the OCSP Responder of the cert
        this.ocspIP = ocspResponderURL.split(":")[0];
        this.ocspPort = new Integer(ocspResponderURL.split(":")[1]);

    }

    public void init(boolean forwardChecking) throws CertPathValidatorException {
        // Do nothing
    }

    public boolean isForwardCheckingSupported() {
        return true;//The isForwardCheckingSupported() should return true if the checker supports forward direction processing. All checkers must support reverse processing. 
    }

    public Set<String> getSupportedExtensions() {
        return null;//objects representing the OIDs of the X.509 extensions that the checker implementation can handle. If the checker does not handle any specific extensions, getSupportedExtensions() should return null. 
    }

    public void check(Certificate cert, Collection<String> extensions) throws CertPathValidatorException {

        X509Certificate x509Cert = (X509Certificate) cert; // This is the certificate we want to check
        BigInteger serial = x509Cert.getSerialNumber(); // Get the serial
        String mess = "";
        try {
            OCSPReq ocspreq = OCSPManager.generateOCSPRequest(ocspResponderCert, serial); // Create an OCSP Request

            byte[] resp = getOCSPResp(ocspreq, ocspIP, ocspPort);

            try {
                OCSPResp response = new OCSPResp(resp); // Parse it to OCSPResp
                mess = OCSPManager.analyseResponse(response, ocspreq, ocspResponderCert); // Analyse the response
            } catch (Exception e) {
                throw new CertPathValidatorException(new String(resp));
            }

        } catch (Exception e) {
            throw new CertPathValidatorException("Could not connect with OCSP Responder");
        }

        if (mess.endsWith("Good"))
            System.out.println("OCSP Response: Certificate: " + serial + " is valid!");
        else
            throw new CertPathValidatorException(mess);
    }

    private byte[] getOCSPResp(OCSPReq ocspReq, String ocspIP, int ocspPort) throws IOException {
        byte[] resp = null;
        try {
            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket c = (SSLSocket) f.createSocket(ocspIP, ocspPort);
            c.startHandshake();
            DataOutputStream w = new DataOutputStream(c.getOutputStream());
            DataInputStream r = new DataInputStream(c.getInputStream());
            w.write(ocspReq.getEncoded());
            resp = read(r);
            w.close();
            r.close();
        } catch (Exception e) {

        }
        return resp;
    }

    public byte[] read(InputStream in) {
        try {
            byte[] res = new byte[4096];
            int read = in.read(res);
            if (read == -1) {
                System.out.println("error !!");
            }

            byte[] res_fitted = new byte[read];
            for (int i = 0; i < read; i++) {
                res_fitted[i] = res[i];
            }
            return res_fitted;
        } catch (Exception e) {
            return null;
        }
    }
}