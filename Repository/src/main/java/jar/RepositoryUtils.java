package jar;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.io.Files;
import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Created by Suavek on 14/03/2017.
 */
public class RepositoryUtils {

    private static X509CRLHolder CRL;
    private static KeyStore CERTIFICATES_REPOSITORY;
    private static RepositoryRecords RR;
    private static String CERT_STORE_PATH = Configuration.get("REPOSITORY_CS_PATH");
    private static String CERT_STORE_PASS = Configuration.get("REPOSITORY_CS_PASS");
    private static String CRL_FILE_PATH = Configuration.get("CRL_FILE_PATH");
    private static String CR_FILE_PATH = Configuration.get("RR_FILE_PATH");

    public static void initRepository() {
        // Read crl from file
        // Read cert-repo (Java Keystore) from file
        try {
            CRL = CRLManager.readCRLFromFile(CRL_FILE_PATH);

        } catch (Exception e) {
            System.err.println("Could not load crl file");
        }
        try {
            CERTIFICATES_REPOSITORY = KeyStoreUtils.getKeyStore(CERT_STORE_PATH, CERT_STORE_PASS);
        } catch (Exception e) {
            System.err.println("Could not load cert-store file");
        }
        // Read certificate records from tile
        // If it does not exists create a new one
        try {
            File certRecordsFile = new File(CR_FILE_PATH);
            if (!certRecordsFile.exists()) {
                Files.createParentDirs(certRecordsFile);
                HashMap<String, HashMap> certificationRecords = Maps.newHashMap();
                FileOutputStream fos = new FileOutputStream(certRecordsFile);
                SerializationUtils.serialize(certificationRecords, fos);
                fos.close();
            } else {
                RR = new RepositoryRecords(certRecordsFile);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void updateCRL(X509CRLHolder crl) throws IOException, KeyStoreException {
        CRLManager.writeCRLToFile(crl, CRL_FILE_PATH);
        String revokedCertAlias = RR.getRevokedCertificateAlias(CRL, crl);
        if (revokedCertAlias != null) {
            deleteCertificateEntry(revokedCertAlias);
            System.out.println("Certificate: CN=" + revokedCertAlias + " Removed From the Repository...");
        }

        CRL = crl;
    }

    public static X509CRLHolder getCRL() throws IOException {
        return CRL;
    }

    public static X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) CERTIFICATES_REPOSITORY.getCertificate(alias);
    }

    public static void setCertificateEntry(String alias, X509Certificate certificate) throws KeyStoreException {
        CERTIFICATES_REPOSITORY.setCertificateEntry(alias, certificate);
        System.out.println("Certificate Published Successfully: " + certificate.getSubjectDN().getName() +
                " , serialNumber=" + certificate.getSerialNumber());
        try {
            KeyStoreUtils.saveKeyStore(CERTIFICATES_REPOSITORY, CERT_STORE_PATH, CERT_STORE_PASS);
            RR.updateRecords(certificate);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }

    public static void deleteCertificateEntry(String alias) throws KeyStoreException {
        CERTIFICATES_REPOSITORY.deleteEntry(alias);
        try {
            KeyStoreUtils.saveKeyStore(CERTIFICATES_REPOSITORY, CERT_STORE_PATH, CERT_STORE_PASS);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }

    private static class RepositoryRecords {

        private HashMap<String, HashMap> certRecords;
        File certRecordsFile;

        public RepositoryRecords(File certRecordsFile) {
            try {
                this.certRecordsFile = certRecordsFile;
                FileInputStream fis = new FileInputStream(certRecordsFile);
                this.certRecords = (HashMap<String, HashMap>) SerializationUtils.deserialize(fis);
                fis.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void updateRecords(X509Certificate certificate) {
            String certSerialNumber = certificate.getSerialNumber().toString();
            String certSubject = CertificateUtils.getSubjectName(certificate);
            String certPublicKeyInfo = certificate.getPublicKey().toString();

            HashMap<String, String> certDetails = Maps.newHashMap();
            certDetails.put(certSubject, certPublicKeyInfo);
            this.certRecords.put(certSerialNumber, certDetails);
            try {
                FileOutputStream fos = new FileOutputStream(certRecordsFile);
                SerializationUtils.serialize(this.certRecords, fos);
                fos.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public String getRevokedCertificateAlias(X509CRLHolder crlOLD, X509CRLHolder crlNEW) {

            List<X509CRLEntryHolder> crlOldRecords = (List<X509CRLEntryHolder>) crlOLD.getRevokedCertificates();
            List<X509CRLEntryHolder> crlNewRecords = (List<X509CRLEntryHolder>) crlNEW.getRevokedCertificates();

            ArrayList<String> oldEntries = Lists.newArrayList();

            for (X509CRLEntryHolder entry : crlOldRecords) {
                oldEntries.add(entry.getSerialNumber().toString());
            }

            ArrayList<String> newEnrties = Lists.newArrayList();
            for (X509CRLEntryHolder entry : crlNewRecords) {
                newEnrties.add(entry.getSerialNumber().toString());
            }
            // remove all old entries
            newEnrties.removeAll(oldEntries);
            String certificateSerialNumber = "";
            try {
                // get new certificate number entry
                certificateSerialNumber = newEnrties.get(0);
            } catch (Exception e) {

            }

            // extract alias from certRecords
            String certificateAlias = this.certRecords.get(certificateSerialNumber).keySet().iterator().next().toString();
            System.out.println("CRL New Certificate Entry: " + "CN=" + certificateAlias + " , serialNumber=" + certificateSerialNumber);
            return certificateAlias;
        }
    }
}
