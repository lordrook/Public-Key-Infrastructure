package jar;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;


public class CRLManager {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create an empty CRL signed with the given private key.
     *
     * @param signerCertificate
     * @param signerPrivateKey
     * @return
     * @throws CertificateParsingException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SecurityException
     * @throws SignatureException
     * @throws CertificateEncodingException
     * @throws CertIOException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws FileNotFoundException
     */
    public static X509CRLHolder createCRL(X509Certificate signerCertificate, PrivateKey signerPrivateKey) throws CertificateParsingException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CertificateEncodingException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, FileNotFoundException {

        Calendar cal = Calendar.getInstance();
        Date currentTime = cal.getTime();
        cal.add(Calendar.DATE, 30);
        Date nextUpdate = cal.getTime();
        X500Name signerName = new X500Name(signerCertificate.getSubjectDN().getName());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(signerName, currentTime);

        crlBuilder.setNextUpdate(nextUpdate);
        // serial number starting from number 1
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        // signing with the private key
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signerPrivateKey);
        return crlBuilder.build(contentSigner);
    }

    public static X509CRLHolder readCRLFromFile(String path) throws IOException {
        return new X509CRLHolder(new FileInputStream(path));
    }

    public static void writeCRLToFile(X509CRLHolder crl, String path) throws IOException {
        File crlFile = new File(path);
        FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
    }

    /**
     * Updates the given CRL by adding given serial
     *
     * @param crl
     * @param signerCertificate
     * @param signerPrivateKey
     * @param revokedCertificateSerialNumber
     * @param reason
     * @return
     */
    public static X509CRLHolder updateCRL(X509CRLHolder crl, X509Certificate signerCertificate, PrivateKey signerPrivateKey, BigInteger revokedCertificateSerialNumber, int reason) {

        try {
            Calendar cal = Calendar.getInstance();
            Date currentTime = cal.getTime();
            cal.add(Calendar.DATE, 30);
            Date nextUpdate = cal.getTime();

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crl.getIssuer(), currentTime);
            // Build on an existing CRL
            crlBuilder.addCRL(crl);
            // Add the serial number that is revoked
            crlBuilder.addCRLEntry(revokedCertificateSerialNumber, currentTime, reason);
            // Set next update time
            crlBuilder.setNextUpdate(nextUpdate);
            // Increment CRL Serial Number by 1
            Extension ex = crl.getExtension(Extension.cRLNumber);
            BigInteger newSerialNumber = new BigInteger(ex.getParsedValue().toString()).add(BigInteger.ONE);

            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signerCertificate));
            crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(newSerialNumber));

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signerPrivateKey);
            return crlBuilder.build(contentSigner);

        } catch (Exception e) {
            return null;
        }
    }


    public static boolean serialNotInCRL(X509CRLHolder crl, BigInteger serial) {
        /*
         * Return true if the serial is not in the crl, false otherwise
		 */
        X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
        if (entry == null) {
            System.out.println("Certificate Revocation Status: " + serial + " - GOOD");
            return true;
        } else {
            RDN cn = crl.getIssuer().getRDNs(BCStyle.CN)[0];
            String issuer = IETFUtils.valueToString(cn.getFirst().getValue());
            // cn.getFirst().getValue() is enough

            if (entry.hasExtensions()) {
                Extension ext = entry.getExtension(Extension.reasonCode);
                if (ext != null) {
                    ASN1Enumerated reasonCode;
                    try {
                        byte[] value = ext.getExtnValue().getEncoded();
                        reasonCode = (ASN1Enumerated) X509ExtensionUtil.fromExtensionValue(value);
                        String reason = "Certificate has been revoked, " +
                                ", reason: " + CRLReason.lookup(reasonCode.getValue().intValue()) +
                                ", revocation date: " + entry.getRevocationDate() +
                                ", authority: " + crl.getIssuer() +
                                ", extension OIDs: " + entry.getExtensionOIDs();
                        System.out.println(reason);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            return false;
        }
    }

    public static X509CRLHolder revokeCertificate(X509CRLHolder crlHolder, String certSerialNumber, X509Certificate caCert, PrivateKey caKey) throws Exception {
        try {
            //X509CRLHolder holder = LDAPUtils.getCRLFromURL(CertificateUtils.crlURLFromCert(caCert)); // Get the CRL of his issuer
            BigInteger serial = new BigInteger(certSerialNumber);
            //Call the method of the CryptoAPI to update an existing CRL
            X509CRLHolder newCRL = updateCRL(crlHolder, caCert, caKey, serial, CRLReason.privilegeWithdrawn);
            return newCRL;
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public static X509CRLHolder getCRLFromRepository(X509Certificate certificate) throws Exception {
        final String crlUrl = CertificateUtils.crlURLFromCert(certificate);
        URL oracle = new URL(crlUrl);
        byte[] bytes = IOUtils.toByteArray(oracle.openStream());
        X509CRLHolder crl = new X509CRLHolder(bytes);
        return crl;
    }

    /**
     * Method checks the CRL signature in accordance with the given certificate
     *
     * @param crl
     * @param caCert
     * @return
     */
    public static boolean isCRLValid(X509CRLHolder crl, X509Certificate caCert) {
        try {
            return crl.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caCert));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
