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

            // 3. Odredi mod i JCE transformation (priprema za ECB/CBC)
            String cipherSpec = args.getCipher();
            if (cipherSpec == null || cipherSpec.isBlank())
                cipherSpec = "aes-256-cbc";
            cipherSpec = cipherSpec.toLowerCase();

            // očekujemo format: aes-<128|192|256>-<ecb|cbc|cfb|ofb|ctr|gcm>
            String[] parts = cipherSpec.split("-");
            if (parts.length != 3) {
                System.err.println("Error: unsupported cipher: " + cipherSpec);
                return StatusCode.UNSUPPORTED_CIPHER;
            }
            String mode = parts[2]; // ecb / cbc (ostalo ćemo kasnije)
            String transformation;
            boolean requiresIv;

            switch (mode) {
                case "ecb":
                    transformation = "AES/ECB/PKCS5Padding";
                    requiresIv = false;
                    break;
                case "cbc":
                    transformation = "AES/CBC/PKCS5Padding";
                    requiresIv = true;
                    break;
                default:
                    System.err.println("Error: only ECB/CBC implemented yet");
                    return StatusCode.UNSUPPORTED_CIPHER;
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
            // 5. UČITAJ IV samo ako je potreban (ECB ne traži IV)
            byte[] ivBytes = null;
            if (requiresIv) {
                String ivPathStr = args.getIvPath();
                if (ivPathStr == null || ivPathStr.isBlank()) {
                    System.err.println("Error: -iv is required for " + cipherSpec);
                    return StatusCode.INVALID_ARGUMENTS;
                }
                byte[] ivB64 = Files.readAllBytes(java.nio.file.Path.of(ivPathStr));
                try {
                    ivBytes = java.util.Base64.getDecoder().decode(ivB64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 iv");
                    return StatusCode.INVALID_IV;
                }
                if (ivBytes.length != 16) {
                    System.err.println("Error: IV must be 16 bytes for AES (16 bytes)");
                    return StatusCode.INVALID_IV;
                }
            }

            // 6. KONFIGURIŠI JCE cipher prema odabranom modu
            // transformation i mode smo već odredili u koraku 1a
            Cipher cipher = Cipher.getInstance(transformation);

            // SecretKeySpec → pakuje bajtove ključa i kaže JCE-u "ovo je AES ključ"
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            // Ako je mod ECB → ne koristi IV (cipher.init sa samo ključem)
            // Ako je mod CBC → koristi i ključ i IV (IvParameterSpec)
            if ("ecb".equals(mode)) {
                // ECB: nema IV
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                // CBC: mora da ima IV od 16 bajtova
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            }

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
                if (out != null && out != System.out)
                    out.close();
            } catch (IOException ignore) {
            }
        }
    }
}
