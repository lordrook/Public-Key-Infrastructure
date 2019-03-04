package jar;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Configuration {

    public static final String CONFIGURATION_FILE = "config";

    public static String get(String propertyName) {

        try {
            Properties property = new Properties();
            property.load(new FileInputStream(CONFIGURATION_FILE));
            String propertyValue = property.getProperty(propertyName);
            if (propertyValue != null) {
                return propertyValue;
            } else {
                System.err.println("Property '" + propertyName + "' not found in the " + CONFIGURATION_FILE + " file.");
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Configuration file :" + CONFIGURATION_FILE + " not found!");
            System.exit(1);
        }
        return null;
    }
}
