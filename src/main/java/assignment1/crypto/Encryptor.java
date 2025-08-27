package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class Encryptor {

    public static int run(ArgumentBundle args) {
        OutputStream out = null;
        try {
            // ulaz
            Path inPath = Path.of(args.getInputPath());
            byte[] plaintext = Files.readAllBytes(inPath);

            // izlaz (fajl ili stdout)
            Path outPath = null;
            String outStr = args.getOutputPath();
            if (outStr != null && !outStr.isBlank()) {
                outPath = Path.of(outStr);
            }
            if (outPath != null) {
                if (Files.exists(outPath) && Files.isDirectory(outPath)) {
                    System.err.println("Error: output path is a directory");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                if (outPath.getParent() != null && !Files.exists(outPath.getParent())) {
                    System.err.println("Error: output directory does not exist");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                out = new FileOutputStream(outPath.toFile());
            } else {
                out = System.out;
            }

            // cipher (za sada CBC; ostale modove dodaćeš kasnije)
            String cipherSpec = args.getCipher();
            if (cipherSpec == null || cipherSpec.isBlank()) cipherSpec = "aes-256-cbc";
            cipherSpec = cipherSpec.toLowerCase();
            if (!cipherSpec.endsWith("-cbc")) {
                System.err.println("Error: only CBC implemented in this step");
                return StatusCode.ENCRYPTION_ERROR;
            }

            // key (Base64 fajl)
            String keyPathStr = args.getKeyPath();
            if (keyPathStr == null || keyPathStr.isBlank()) {
                System.err.println("Error: key is required");
                return StatusCode.INVALID_ARGUMENTS;
            }
            byte[] keyBytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of(keyPathStr)));
            int bits = keyBytes.length * 8;
            if (bits != 128 && bits != 192 && bits != 256) {
                System.err.println("Error: invalid key length");
                return StatusCode.INVALID_KEY;
            }

            // IV (Base64 fajl, 16 bajtova)
            String ivPathStr = args.getIvPath();
            if (ivPathStr == null || ivPathStr.isBlank()) {
                System.err.println("Error: -iv is required for CBC");
                return StatusCode.INVALID_ARGUMENTS;
            }
            byte[] ivBytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of(ivPathStr)));
            if (ivBytes.length != 16) {
                System.err.println("Error: IV must be 16 bytes for AES");
                return StatusCode.INVALID_IV;
            }

            // JCE: AES/CBC/PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

            byte[] ciphertext = cipher.doFinal(plaintext);
            out.write(ciphertext);
            out.flush();

            return StatusCode.SUCCESS;
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            return StatusCode.FILE_WRITE_ERROR;
        } catch (IllegalArgumentException e) {
            // Base64 decode i slične validacije
            System.err.println("Error: " + e.getMessage());
            return StatusCode.ENCRYPTION_ERROR;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return StatusCode.ENCRYPTION_ERROR;
        } finally {
            try {
                if (out != null && out != System.out) out.close();
            } catch (IOException ignore) {}
        }
    }
}
