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
            // 1. UČITAJ ULAZNI FAJL
            Path inPath = Path.of(args.getInputPath());
            byte[] plaintext = Files.readAllBytes(inPath);

            // 2. PRIPREMI IZLAZ (ili fajl, ili stdout)
            Path outPath = null;
            String outStr = args.getOutputPath();
            if (outStr != null && !outStr.isBlank()) {
                outPath = Path.of(outStr);
            }
            if (outPath != null) {
                // ako je direktorijum → greška
                if (Files.exists(outPath) && Files.isDirectory(outPath)) {
                    System.err.println("Error: output path is a directory");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                // ako parent dir ne postoji → greška
                if (outPath.getParent() != null && !Files.exists(outPath.getParent())) {
                    System.err.println("Error: output directory does not exist");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                out = new FileOutputStream(outPath.toFile());
            } else {
                // ako nije zadat -out → koristi stdout
                out = System.out;
            }

            // 3. PROVERI cipher (za sada samo CBC implementiran)
            String cipherSpec = args.getCipher();
            if (cipherSpec == null || cipherSpec.isBlank()) cipherSpec = "aes-256-cbc";
            cipherSpec = cipherSpec.toLowerCase();
            if (!cipherSpec.endsWith("-cbc")) {
                System.err.println("Error: only CBC implemented in this step");
                return StatusCode.ENCRYPTION_ERROR;
            }

            // 4. UČITAJ KLJUČ (Base64 fajl)
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

            // 5. UČITAJ IV (Base64 fajl, tačno 16 bajtova)
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

            // 6. KONFIGURIŠI JCE cipher: AES/CBC/PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));

            // 7. ENKRIPCIJA
            byte[] ciphertext = cipher.doFinal(plaintext);

            // 8. UPIS U FAJL ILI STDOUT
            out.write(ciphertext);
            out.flush();

            return StatusCode.SUCCESS;

        } catch (IOException e) {
            // greške vezane za fajl (čitanje/pisanje)
            System.err.println("Error: " + e.getMessage());
            return StatusCode.FILE_WRITE_ERROR;
        } catch (IllegalArgumentException e) {
            // greške kod Base64 decode i validacije
            System.err.println("Error: " + e.getMessage());
            return StatusCode.ENCRYPTION_ERROR;
        } catch (Exception e) {
            // sve ostale greške (npr. JCE init)
            System.err.println("Error: " + e.getMessage());
            return StatusCode.ENCRYPTION_ERROR;
        } finally {
            // 9. ZATVARANJE STREAMA
            try {
                if (out != null && out != System.out) out.close();
            } catch (IOException ignore) {}
        }
    }
}
