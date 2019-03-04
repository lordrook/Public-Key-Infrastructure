package jar;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.List;

/**
 * Created by Suavek on 23/03/2017.
 */
public class AuthenticationHandler {


    public static boolean verifyUserCredentials(byte[] credentials) {
        String[] userCredentials = new String(credentials).split(":");
        String username = userCredentials[0];
        String password = userCredentials[1];

        try {
            File file = new File("users.csv");
            Reader fileReader = new FileReader(file);
            CSVFormat csvFileFormat = CSVFormat.DEFAULT.withFirstRecordAsHeader();
            CSVParser csvFileParser = new CSVParser(fileReader, csvFileFormat);
            List<CSVRecord> csvRecordList = csvFileParser.getRecords();
            fileReader.close();
            for (CSVRecord user : csvRecordList) {
                if (username.equals(user.get("username")) && password.equals(user.get("password")))
                    return true;

            }
        } catch (Exception e) {
            System.err.println("Could not find user records");
        }


        return false;
    }
}
