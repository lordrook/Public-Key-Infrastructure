package jar;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by Suavek on 01/03/2017.
 */
public class CSRManager {

    public static X509Certificate retrieveCertificateFromCSR(PKCS10CertificationRequest inputCSR, PrivateKey signerPrivateKey, X509Certificate signerCertificate, String crlUrl, String ocspUrl) throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        X500Name subjectName = inputCSR.getSubject();
        SubjectPublicKeyInfo subjectPublicKeyInfo = inputCSR.getSubjectPublicKeyInfo();
        X509Certificate endUserCertificate = CertificateUtils.createSignedCertificateEndUser(signerPrivateKey, signerCertificate, subjectName, subjectPublicKeyInfo, crlUrl, ocspUrl);
        return endUserCertificate;
    }

    /**
     * Method generates a csr based on the cn and keyPair
     *
     * @param name
     * @param keyPair
     * @return
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest generateCSR(String name, KeyPair keyPair) throws NoSuchAlgorithmException, OperatorCreationException {
        X500Name subjectName = new X500Name("cn=" + name);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(subjectName, keyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
        return csrBuilder.build(contentSigner);
    }


}
