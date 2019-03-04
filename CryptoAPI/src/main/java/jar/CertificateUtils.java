package jar;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;


public class CertificateUtils {

    public static void saveCertToFile(X509Certificate cert) {
        try {
            File crlFile = new File(getSubjectName(cert) + ".cer");
            FileUtils.writeByteArrayToFile(crlFile, cert.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate certificateFromByteArray(byte[] bytes) {
        /*
         * Return an X509Certificate from a certificate encoded in byte[]
		 */
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            return null;
        }
    }

    public static String crlURLFromCert2(X509Certificate cert) {
        /*
         * Return the crlDistributionPoints extension from a certificate
		 */
        String url;
        try {
            url = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(X509Extension.cRLDistributionPoints.getId()))).getDistributionPoints()[0].getDistributionPoint().getName().toASN1Primitive().toString();
            return url.substring(4, url.length() - 1);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String crlURLFromCert(X509Certificate cert) {
        String url;
        try {
            byte[] crldpExtension = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            ASN1Primitive value = X509ExtensionUtil.fromExtensionValue(crldpExtension);
            CRLDistPoint crldp = CRLDistPoint.getInstance(value);
            DistributionPoint[] distributionPoints = crldp.getDistributionPoints();
            url = distributionPoints[0].getDistributionPoint().getName().toASN1Primitive().toString();
            return url.substring(4, url.length() - 1);
        } catch (IOException e) {
            e.printStackTrace();
            return null;

        }
    }

    public static String ocspURLFromCert(X509Certificate cert) {
        /*
         * Return the OCSP Responder address contained in the certificate
		 * More precisely the it is contained in the authorityInfoAccess extension
		 */
        try {
            return AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue(X509Extension.authorityInfoAccess.getId()))).getAccessDescriptions()[0].getAccessLocation().getName().toASN1Primitive().toString().split("://")[1];
        } catch (Exception e) {
            return null;
        }
    }

    public static Certificate[] createNewChain(Certificate[] chain, X509Certificate cert) {
        /*
         * Add the given certificate to the chain Certificate[]
		 */
        Certificate[] newchain = new Certificate[chain.length + 1];
        for (int i = 0; i < chain.length; i++)
            newchain[i] = chain[i];
        newchain[chain.length] = cert;
        return newchain;
    }

    public static String getSubjectName(X509Certificate cert) {
        X500Name x500name = null;
        try {
            x500name = new JcaX509CertificateHolder(cert).getSubject();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }


    public static X509Certificate createSelfSignedCertificate(String subjectName, KeyPair keyPair, String crlUrl, String ocspUrl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        /* EXTENSION:												CRITICAL
         * basicConstraints(true) pathlen(1)				true
		 * authorityKeyIdentifier(pas utile)
		 * subjectKeyIdentifier:hash							false
		 * KeyUsage: keyCertSign
		 *
		 * EXTENDEDKeyUsage
		 * nsComment:"PKI Root Certificate"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */

        // Issuer is the same as subject
        String issuerName = subjectName;
        BigInteger serialNumber = BigInteger.ONE;

        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 10);
        Date notAfter = cal.getTime();

        X500Name subjectFormatted = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subjectName).build();
        X500Name issuerFormatted = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerFormatted, serialNumber, notBefore, notAfter, subjectFormatted, keyPair.getPublic());

        //Signer will be the same ourselves
        //Signed by its own private key
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());

        //------------------------- Extensions ------------------------
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1)); //Should be critics

        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, true, keyUsage); //KeyUsage must be critic

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
        DERSequence derSequence = new DERSequence(distributionPoint);
        builder.addExtension(Extension.cRLDistributionPoints, false, derSequence);


        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
        AuthorityInformationAccess acc = new AuthorityInformationAccess(Extension.authorityInfoAccess, gn);
        builder.addExtension(Extension.authorityInfoAccess, false, acc);

        X509CertificateHolder holder = builder.build(contentSigner);

        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    public static X509Certificate createSignedCertificateEndUser(PrivateKey signerPrivateKey, X509Certificate signerCertificate, X500Name subjectName, SubjectPublicKeyInfo subjectPublicKeyInfo, String crlUrl, String ocspUrl) throws IOException, OperatorCreationException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {

       /*
         * Sign the given OKCS10CertificationRequest with the given private key
		 */

        /* EXTENSION:																	CRITICAL
         * basicConstraints(false)													true
		 * authorityKeyIdentifier keyid:always
		 * subjectKeyIdentifier:hash
		 * keyUsage: cRLSign, digitalSignature, nonRepudiation
		 * extendedKeyUsage: OCSPSigning									false
		 * nsComment "Certificate for CRL and OCSP Signing"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(signerPrivateKey.getEncoded());

        X500Name issuerName = new X500Name(signerCertificate.getSubjectDN().getName());

        String currentTimeInMills = String.valueOf(System.currentTimeMillis());
        BigInteger certificateSerialNumber = new BigInteger(currentTimeInMills);

        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 2); // Define the validity of 2 years
        Date notAfter = calendar.getTime();


        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(issuerName, certificateSerialNumber, notBefore, notAfter, subjectName, subjectPublicKeyInfo);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);

        //------------------------- Extensions ------------------------
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCertificate));

        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.digitalSignature);
        certificateGenerator.addExtension(Extension.keyUsage, true, keyUsage);

        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
        DERSequence derSequence = new DERSequence(distributionPoint);
        certificateGenerator.addExtension(Extension.cRLDistributionPoints, false, derSequence);

        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
        AuthorityInformationAccess acc = new AuthorityInformationAccess(Extension.authorityInfoAccess, gn);
        certificateGenerator.addExtension(Extension.authorityInfoAccess, false, acc);


        X509CertificateHolder holder = certificateGenerator.build(sigGen);
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    public static X509Certificate createSignedCertificateIntermediate(String subject, KeyPair keyPair, X509Certificate signerCertificate, PrivateKey issuerPrivateKey, String crlUrl, String ocspUrl) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        /* EXTENSION:																CRITICAL
         * basicConstraint(true)pathlen:0									true
		 * authorityKeyIdentifier keyid:always, issuer:always		false
		 * subjectKeyIdentifier:hash											false
		 * KeyUsage: KeyCertSign
		 *
		 * ExtendedKeyUsage:
		 * nsComment: "Intermediate CA for Users Cert"
		 * cRLDistributionPoint  ldap://localhost.org/RootCA/crl.crl
		 * authorityInfoAccess: http://ocsp.localhost.org
		 */

        X500Name issuerName = new X500Name(signerCertificate.getSubjectDN().getName());
        X500Name subjectName = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();

        String currentTimeInMills = String.valueOf(System.currentTimeMillis());
        BigInteger certificateSerialNumber = new BigInteger(currentTimeInMills);

        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 10); // Define the validity of 2 years
        Date notAfter = calendar.getTime();

        //JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, certificateSerialNumber, notBefore, notAfter, subjectName, keyPair.getPublic());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(signerCertificate, certificateSerialNumber, notBefore, notAfter, new X500Principal("CN=" + subject), keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(issuerPrivateKey);

        //------------------------- Extensions ------------------------
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        builder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCertificate));

        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        // Intermediate CA are just allowed to sign certificate (which is good enough)
//        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        builder.addExtension(Extension.keyUsage, true, keyUsage);

        if (crlUrl != null) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl));
            GeneralNames gns = new GeneralNames(gn);
            DistributionPointName dpn = new DistributionPointName(gns);
            DistributionPoint distp = new DistributionPoint(dpn, null, null);
            DERSequence seq = new DERSequence(distp);
            builder.addExtension(Extension.cRLDistributionPoints, false, seq);
        }
        if (ocspUrl != null) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(ocspUrl));
            AuthorityInformationAccess acc = new AuthorityInformationAccess(Extension.authorityInfoAccess, gn);
            builder.addExtension(Extension.authorityInfoAccess, false, acc);
        }
        //----------------------------------------------------------------

        X509CertificateHolder holder = builder.build(contentSigner);

        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }
}
