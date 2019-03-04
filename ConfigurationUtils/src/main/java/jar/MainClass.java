package jar;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CRLHolder;

import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Created by Suavek on 06/03/2017.
 */
public class MainClass {

    public static void main(String... args) {

        try {

            String CRL_URL = "http://" + Configuration.get("IP_REPOSITORY") + ":" + Configuration.get("PORT_REPOSITORY_HTTP") + "/certificaterevocationlist.crl";
            String OCSP_URL = "http://" + Configuration.get("IP_VA") + ":" + Configuration.get("PORT_VA");

            // ---------------------- CA SETUP
            String caName = Configuration.get("CA_ALIAS");
            String caKeyStorePath = Configuration.get("CA_KS_PATH");
            String caKeyStorePassword = Configuration.get("CA_KS_PASS");
            String caTrustStorePath = Configuration.get("CA_TS_PATH");
            String caTrustStorePassword = Configuration.get("CA_TS_PASS");
            String caCertificateAlias = Configuration.get("CA_KS_ALIAS_CERT");
            String caKeyAlias = Configuration.get("CA_KS_ALIAS_KEY");
            Integer keySize = 1024;
            // Generate new key pair
            KeyPair caKeyPair = CryptoTools.generateKeyPair(1024);
            // Generate self signed certificate for the CA
            X509Certificate caCert = CertificateUtils.createSelfSignedCertificate(caName, caKeyPair, CRL_URL, OCSP_URL);
            // Store private and cert in the CA keystore
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, caKeyStorePath, caKeyStorePassword);
            KeyStoreUtils.setKeyEntry(caKeyAlias, caKeyPair.getPrivate(), caCert, caKeyStorePath, caKeyStorePassword);
            saveCertToFile(caCert, "ca");

            // ---------------------- RA SETUP
            String raName = Configuration.get("RA_ALIAS");
            String raKeyStorePath = Configuration.get("RA_KS_PATH");
            String raKeyStorePassword = Configuration.get("RA_KS_PASS");
            String raTrustStorePath = Configuration.get("RA_TS_PATH");
            String raTrustStorePassword = Configuration.get("RA_TS_PASS");
            String raCertificateAlias = Configuration.get("RA_KS_ALIAS_CERT");
            String raKeyAlias = Configuration.get("RA_KS_ALIAS_KEY");

            // Generate new key pair
            KeyPair raKeyPair = CryptoTools.generateKeyPair(1024);
            // Generate self signed certificate of the CA
            X509Certificate raCert = CertificateUtils.createSignedCertificateIntermediate(raName, raKeyPair, caCert, caKeyPair.getPrivate(), CRL_URL, OCSP_URL);
            // Store private and cert in the CA keystore
            KeyStoreUtils.setCertificateEntry(raCertificateAlias, raCert, raKeyStorePath, raKeyStorePassword);
            KeyStoreUtils.setKeyEntry(raKeyAlias, raKeyPair.getPrivate(), raCert, raKeyStorePath, raKeyStorePassword);
            saveCertToFile(raCert, "ra");

            // ---------------------- VA SETUP
            String vaName = Configuration.get("VA_ALIAS");
            String vaKeyStorePath = Configuration.get("VA_KS_PATH");
            String vaKeyStorePassword = Configuration.get("VA_KS_PASS");
            String vaCertificateAlias = Configuration.get("VA_KS_ALIAS_CERT");
            String vaKeyAlias = Configuration.get("VA_KS_ALIAS_KEY");

            // Generate new key pair
            KeyPair vaKeyPair = CryptoTools.generateKeyPair(1024);
            // Generate self signed certificate of the CA
            X509Certificate vaCert = CertificateUtils.createSignedCertificateIntermediate(vaName, vaKeyPair, caCert, caKeyPair.getPrivate(), CRL_URL, OCSP_URL);
            // Store private and cert in the CA keystore
            KeyStoreUtils.setCertificateEntry(vaCertificateAlias, vaCert, vaKeyStorePath, vaKeyStorePassword);
            KeyStoreUtils.setKeyEntry(vaKeyAlias, vaKeyPair.getPrivate(), vaCert, vaKeyStorePath, vaKeyStorePassword);
            saveCertToFile(vaCert, "va");

            // ---------------------- REPOSITORY SETUP
            String repositoryName = Configuration.get("REPOSITORY_ALIAS");
            String repositoryKeyStorePath = Configuration.get("REPOSITORY_KS_PATH");
            String repositoryKeyStorePassword = Configuration.get("REPOSITORY_KS_PASS");
            String repositoryTrustStorePath = Configuration.get("REPOSITORY_TS_PATH");
            String repositoryTrustStorePassword = Configuration.get("CA_TS_PASS");
            String repositoryCertificateAlias = Configuration.get("REPOSITORY_KS_ALIAS_CERT");
            String repositoryKeyAlias = Configuration.get("REPOSITORY_KS_ALIAS_KEY");

            // Generate new key pair
            KeyPair repositoryKeyPair = CryptoTools.generateKeyPair(1024);
            // Generate self signed certificate of the CA
            X509Certificate repositoryCert = CertificateUtils.createSignedCertificateIntermediate(repositoryName, repositoryKeyPair, caCert, caKeyPair.getPrivate(), CRL_URL, OCSP_URL);
            // Store private and cert in the CA keystore
            KeyStoreUtils.setCertificateEntry(repositoryCertificateAlias, repositoryCert, repositoryKeyStorePath, repositoryKeyStorePassword);
            KeyStoreUtils.setKeyEntry(repositoryKeyAlias, repositoryKeyPair.getPrivate(), repositoryCert, repositoryKeyStorePath, repositoryKeyStorePassword);
            //
            saveCertToFile(repositoryCert, "repository");


            // TRUST STORES SETUP
            // ADD RA cert to CA keystore
            KeyStoreUtils.setCertificateEntry(raCertificateAlias, raCert, caKeyStorePath, caKeyStorePassword);
            KeyStoreUtils.setCertificateEntry(repositoryCertificateAlias, repositoryCert, caKeyStorePath, caKeyStorePassword);
            // ADD CA cert to RA keystore
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, raKeyStorePath, raKeyStorePassword);
            // ADD CA cert to REPOSITORY keystore
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, repositoryKeyStorePath, repositoryKeyStorePassword);

            // TRUST STORES SETUP
            // ADD RA cert to CA keystore
            KeyStoreUtils.setCertificateEntry(raCertificateAlias, raCert, caTrustStorePath, caTrustStorePassword);
            KeyStoreUtils.setCertificateEntry(repositoryCertificateAlias, repositoryCert, caTrustStorePath, caTrustStorePassword);
            // ADD CA cert to RA keystore
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, raTrustStorePath, raTrustStorePassword);
            // ADD CA cert to REPOSITORY keystore
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, repositoryTrustStorePath, repositoryTrustStorePassword);

            // ADD CA,RA,CA,REPOSITORY certs to cert store
            String repositoryCertStorePath = Configuration.get("REPOSITORY_CS_PATH");
            String repositoryCertStorePassword = Configuration.get("REPOSITORY_CS_PASS");
            KeyStoreUtils.setCertificateEntry(caCertificateAlias, caCert, repositoryCertStorePath, repositoryCertStorePassword);
            KeyStoreUtils.setCertificateEntry(raCertificateAlias, raCert, repositoryCertStorePath, repositoryCertStorePassword);
            KeyStoreUtils.setCertificateEntry(vaCertificateAlias, vaCert, repositoryCertStorePath, repositoryCertStorePassword);
            KeyStoreUtils.setCertificateEntry(repositoryCertificateAlias, repositoryCert, repositoryCertStorePath, repositoryCertStorePassword);

            // CRL SETUP
            // Create and publish CRL on LDAP
            X509CRLHolder crlRoot = CRLManager.createCRL(caCert, caKeyPair.getPrivate());
            //////////////////////////////////////////////////////LDAPUtils.setCRL(crlRoot);

            String crlFileName = Configuration.get("CRL_FILE_PATH");
            File crlFile = new File(crlFileName);
            FileUtils.writeByteArrayToFile(crlFile, crlRoot.getEncoded());

        } catch (Exception e) {
            //TODO log exceptions
            System.out.println(e);
        }
    }

    private static void saveCertToFile(X509Certificate caCert, String name) throws CertificateEncodingException, IOException {
        File file = new File(name + ".cer");
        byte[] buf = caCert.getEncoded();
        FileOutputStream os = new FileOutputStream(file);
        os.write(buf);
        Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
        wr.write(new sun.misc.BASE64Encoder().encode(buf));
        wr.flush();
        wr.close();
    }
}
