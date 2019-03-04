package jar;

import java.util.Scanner;

/**
 * Created by Suavek on 24/03/2017.
 */
public class ClientUtils {

    public static String getUserCredentials() {
        System.out.println("Please enter your user name: ");
        String name = new Scanner(System.in).nextLine();
        System.out.println("Please enter your password: ");
        String password = new Scanner(System.in).nextLine();
        return new String(name + ":" + password);
    }
}
