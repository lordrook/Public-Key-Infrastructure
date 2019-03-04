package jar;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

public class PathChecking {

    public static boolean checkPathUserCertificate(X509Certificate userCert, boolean checkCRL, PKIXCertPathChecker checker, X509Certificate[] chain, X509Certificate rootCert) throws Exception {


        Security.addProvider(new BouncyCastleProvider());
        System.setProperty("com.sun.security.enableCRLDP", "true");

        // load the cert to be checked
        Vector<X509Certificate> certs = new Vector<X509Certificate>();
        for (X509Certificate c : chain) {
            certs.add(c);
        }
        certs.add(userCert);
        // init cert path
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        CertPath certPath = certificateFactory.generateCertPath(certs);

        // init trusted certs
        TrustAnchor trustedAnchor = new TrustAnchor(rootCert, null);
        Set<TrustAnchor> trustedCerts = new HashSet<TrustAnchor>();
        trustedCerts.add(trustedAnchor);

        // init PKIX parameters
        PKIXParameters params = new PKIXParameters(trustedCerts);
        // set to check clr
        //params.setRevocationEnabled(true);

        if (checkCRL) {
            X509CRLHolder crl = CRLManager.getCRLFromRepository(rootCert);
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singletonList(crl))));

        } else {
            // load the CRL
            params.addCertPathChecker(checker);
            params.setRevocationEnabled(false);
        }


        try {
            // perform validation i.e. check that crl are not outdated, certificate valid well signed etc
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult cpv_result = (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
            X509Certificate trustedCert = (X509Certificate) cpv_result.getTrustAnchor().getTrustedCert();
            System.out.println("Certificate Path Validated Successfully: " + userCert.getSubjectDN().getName() +
                    " , serialNumber=" + userCert.getSerialNumber() + ", ISSUER " + trustedCert.getSubjectDN().getName());
            return true;
        } catch (CertPathValidatorException e) {
            System.out.println("Validation Failed, details: " + e.getMessage());
            if (e.getMessage().contains("OCSP Responder")) {
                throw new Exception(e.getMessage());
            }
            return false;
        }
    }


}


