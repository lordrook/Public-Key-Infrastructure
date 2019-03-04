package jar;

import com.google.common.collect.Maps;
import com.google.common.io.Files;
import org.apache.commons.lang.SerializationUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;

/**
 * Created by Suavek on 02/04/2017.
 */
public class TestHashmap {

    public static void main(String... a) throws IOException {


        String crFileName = "test1" + ".cr";

        // create cert records file if it does not exists
        File certRecordsFile = new File(crFileName);
        if (!certRecordsFile.exists()) {
            Files.createParentDirs(certRecordsFile);
            HashMap<String, HashMap> certificationRecords = Maps.newHashMap();
            SerializationUtils.serialize(certificationRecords, new FileOutputStream(certRecordsFile));
        }

        //Retrieve cert records file from filesystem
        HashMap<String, HashMap> certRecords = (HashMap<String, HashMap>) SerializationUtils.deserialize(new FileInputStream(certRecordsFile));
        // create new record of subject -> public key tuple
        String certSubject = "test subject";
        String certPublicKeyInfo = "97123496129347812093791286398712937812937192837";
        HashMap<String, String> certDetails = Maps.newHashMap();
        certDetails.put(certSubject, certPublicKeyInfo);
        // create new record of cert number -> (subject -> public key) tuple
        String certSerialNumber = "55555555";
        certRecords.put(certSerialNumber, certDetails);
        // save to disc
        SerializationUtils.serialize(certRecords, new FileOutputStream(certRecordsFile));

        HashMap<String, HashMap> certRecords2 = (HashMap<String, HashMap>) SerializationUtils.deserialize(new FileInputStream(certRecordsFile));

        String subjectName2 = certRecords2.get(certSerialNumber).keySet().iterator().next().toString();
        int ooo = 0;
//        try {
//
//            HashMap aaaa = as.get(certSerialNumber);
//            String key = aaaa.keySet().iterator().next().toString();
//            int ooo = 0;
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        }

        int y = 0;
    }
}
