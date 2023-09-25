package org.example;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;
import java.util.Scanner;
import java.util.UUID;

public class FileEncryptor1 {
    private static final Scanner scanner = new Scanner(System.in);
    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";

    public static void main(String[] args) {
        String mode = getMode();
        if (mode == null) return;
        String filePath = getFilePath();
        if (filePath == null) return;
        String outputFile = getOutputFile(mode, filePath);
        if (outputFile == null) return;
        cryptionProssecc(filePath, outputFile, mode);
    }

    private static void cryptionProssecc(String filePath, String outputFile, String mode) {
        try (FileInputStream inputFileStream = new FileInputStream(filePath);
             FileOutputStream outputFileStream = new FileOutputStream(outputFile)) {
            String customKey = getCustomKey();
            if (customKey == null) return;
            Key key = new SecretKeySpec(Arrays.copyOf(customKey.getBytes(),16), "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            if (cipherInit(mode, cipher, key)) return;

            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputFileStream, cipher);

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputFileStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }

            cipherOutputStream.close();

            System.out.println(mode + "ion completed. Output file: " + outputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean cipherInit(String mode, Cipher cipher, Key key) throws InvalidKeyException {
        if (mode.equals(ENCRYPT)) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else if (mode.equals(DECRYPT)) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
            return true;
        }
        return false;
    }

    private static String getCustomKey() {
        System.out.println("Enter key word.");
        String customKey = scanner.nextLine();
        if (customKey.length()>16) {
            System.out.println("Invalid key. Key must be 16 or less characters long.");
            return null;
        }
        return customKey;
    }

    private static String getOutputFile(String mode, String filePath) {
        String outputFile = "";
        if (mode.equalsIgnoreCase(ENCRYPT)) {
            String[] split = filePath.split("\\.");
            String extention = split[split.length - 1];
            outputFile = UUID.randomUUID()+"."+extention + ".enc";
        } else if (mode.equalsIgnoreCase(DECRYPT) && filePath.endsWith(".enc")) {
            outputFile = filePath.substring(0, filePath.length() - 4);
        } else {
            System.out.println("Invalid mode or file extension. Use 'encrypt' or 'decrypt' and ensure the file has the '.enc' extension for decryption.");
            return null;
        }
        return outputFile;
    }

    private static String getFilePath() {
        System.out.println("Enter path of the file you want to process.");
        String filePath = scanner.nextLine();
        if (checkIsFileAvailable(filePath)) return null;
        return filePath;
    }

    private static boolean checkIsFileAvailable(String filePath) {
        if (!Files.exists(Path.of(filePath))) {
            System.err.println("File not found.");
            return true;
        }
        return false;
    }

    private static String getMode() {
        System.out.println("Enter mode. Use 'encrypt' or 'decrypt'.");
        String mode = scanner.nextLine();
        if (checkMode(mode)) return null;
        return mode;
    }

    private static boolean checkMode(String mode) {
        if (!mode.equalsIgnoreCase(ENCRYPT) && !mode.equalsIgnoreCase(DECRYPT)) {
            System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
            return true;
        }
        return false;
    }
}
