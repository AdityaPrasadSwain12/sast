import java.sql.*;
import java.security.MessageDigest;
import java.util.Scanner;
    
public class VulnerableApp {

    // VULN 1: Hardcoded password (CWE-798)
    private static final String ADMIN_PASSWORD = "SuperSecret123";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // VULN 2: SQL Injection (CWE-89)
        System.out.print("Enter user ID: ");
        String userId = scanner.nextLine();
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "root", "");
            Statement stmt = conn.createStatement();
            // Unsafe concatenation – attacker can input "1 OR 1=1"
            String query = "SELECT * FROM users WHERE id = " + userId;
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("User: " + rs.getString("username"));
            }
            conn.close();
        } catch (Exception e) {
            // VULN 3: Empty exception handler (CWE-390) – silently swallows all errors
        }

        // VULN 4: MD5 weak hash (CWE-327)
        System.out.print("Enter password to hash: ");
        String pwd = scanner.nextLine();
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(pwd.getBytes());
            System.out.println("MD5 hash: " + bytesToHex(digest));
        } catch (Exception e) {
            // Another empty handler
        }
        scanner.close();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}