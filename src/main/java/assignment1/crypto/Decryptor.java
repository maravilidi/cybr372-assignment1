package assignment1.crypto;

import assignment1.cli.ArgumentBundle;
import assignment1.cli.StatusCode;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;
import java.io.*;
import java.util.Base64;

public class Decryptor {

    public static int run(ArgumentBundle args) {
        OutputStream out = null;
        try {
            // (1) UČITAVANJE ULAZNOG FAJLA (ciphertext)
            // Ako fajl ne postoji, uhvatićemo NoSuchFileException niže i vratiti FILE_NOT_FOUND.
            Path inPath = Path.of(args.getInputPath());
            byte[] ciphertext = Files.readAllBytes(inPath);

            // (2) PRIPREMA IZLAZA: ili fajl (-out) ili stdout ako -out nije zadat
            Path outPath = null;
            String outStr = args.getOutputPath();
            if (outStr != null && !outStr.isBlank()) {
                outPath = Path.of(outStr);
            }

            if (outPath != null) {
                // ako je putanja direktorijum → greška
                if (Files.exists(outPath) && Files.isDirectory(outPath)) {
                    System.err.println("Error: output path is a directory");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                // ako parent direktorijum ne postoji → greška
                if (outPath.getParent() != null && !Files.exists(outPath.getParent())) {
                    System.err.println("Error: output directory does not exist");
                    return StatusCode.FILE_WRITE_ERROR;
                }
                // kreiramo/overwriting fajl
                out = new FileOutputStream(outPath.toFile());
            } else {
                // ako -out nije zadat → pišemo na stdout
                out = System.out;
            }

            // (3) PARSIRANJE -cipher SPECIFIKACIJE
            // U ovom koraku podržavamo samo ECB i CBC (ostalo ćemo dodati kasnije).
            String cipherSpec = args.getCipher();
            if (cipherSpec == null || cipherSpec.isBlank()) cipherSpec = "aes-256-cbc";
            cipherSpec = cipherSpec.toLowerCase();

            // Očekivani format: "aes-<128|192|256>-<ecb|cbc|...>"
            String[] parts = cipherSpec.split("-");
            if (parts.length != 3) {
                System.err.println("Error: unsupported cipher: " + cipherSpec);
                return StatusCode.UNSUPPORTED_CIPHER;
            }

            String mode = parts[2];          // ecb ili cbc (za sada)
            String transformation;           // JCE transformacija
            boolean requiresIv;              // da li je potreban IV

            switch (mode) {
                case "ecb":
                    // ECB ne koristi IV; padding je PKCS5 (tj. PKCS7 u JCE terminologiji)
                    transformation = "AES/ECB/PKCS5Padding";
                    requiresIv = false;
                    break;
                case "cbc":
                    // CBC zahteva IV dužine 16 bajtova; takođe PKCS5Padding
                    transformation = "AES/CBC/PKCS5Padding";
                    requiresIv = true;
                    break;
                default:
                    // Za sada odbijamo sve ostalo (cfb/ofb/ctr/gcm) – dodaćemo u sledećim koracima
                    System.err.println("Error: only ECB/CBC implemented yet");
                    return StatusCode.UNSUPPORTED_CIPHER;
            }

            // (4) UČITAVANJE KLJUČA IZ FAJLA (Base64)
            // U ovom koraku radimo samo sa -key; granu sa -pass/-salt dodajemo kasnije.
            String keyPathStr = args.getKeyPath();
            if (keyPathStr == null || keyPathStr.isBlank()) {
                System.err.println("Error: key is required");
                return StatusCode.INVALID_ARGUMENTS;
            }

            byte[] keyBytes;
            try {
                // fajl sadrži base64-enkodovan sirovi ključ (16/24/32 bajta)
                keyBytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of(keyPathStr)));
            } catch (IllegalArgumentException e) {
                // Base64 decode nije uspeo → neispravan ključ
                System.err.println("Error: invalid base64 key");
                return StatusCode.INVALID_KEY;
            }

            // Provera dužine ključa: dozvoljeni su 128/192/256 bita
            int bits = keyBytes.length * 8;
            if (bits != 128 && bits != 192 && bits != 256) {
                System.err.println("Error: invalid key length");
                return StatusCode.INVALID_KEY;
            }

            // (5) UČITAVANJE IV-A (ako je potreban)
            byte[] ivBytes = null;
            if (requiresIv) {
                String ivPathStr = args.getIvPath();
                if (ivPathStr == null || ivPathStr.isBlank()) {
                    System.err.println("Error: -iv is required for " + cipherSpec);
                    return StatusCode.INVALID_ARGUMENTS;
                }
                try {
                    // IV je takođe base64-enkodovan u fajlu
                    ivBytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of(ivPathStr)));
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 iv");
                    return StatusCode.INVALID_IV;
                }
                // Za AES-ECB IV ne postoji, za AES-CBC mora biti tačno 16 bajtova
                if (ivBytes.length != 16) {
                    System.err.println("Error: IV must be 16 bytes for AES");
                    return StatusCode.INVALID_IV;
                }
            }

            // (6) KONFIGURACIJA I INICIJALIZACIJA JCE Cipher-a ZA DEKRIPCJU
            Cipher cipher = Cipher.getInstance(transformation);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            if ("ecb".equals(mode)) {
                // ECB: bez IV-a
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                // CBC: sa IV-om (IvParameterSpec)
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            }

            // (7) DEKRIPCIJA (doFinal) — može baciti npr. BadPaddingException za pogrešan ključ/IV
            byte[] plaintext = cipher.doFinal(ciphertext);

            // (8) UPIS PLAINTEXT-A U IZLAZ
            out.write(plaintext);
            out.flush();

            // Uspešan završetak
            return StatusCode.SUCCESS;

        } catch (NoSuchFileException e) {
            // ULAZNI FAJL NE POSTOJI
            System.err.println("Error: input file not found: " + e.getFile());
            return StatusCode.FILE_NOT_FOUND;
        } catch (IOException e) {
            // Greške čitanja/pisanja fajlova
            System.err.println("Error: " + e.getMessage());
            return StatusCode.FILE_WRITE_ERROR;
        } catch (Exception e) {
            // Ostale greške (npr. BadPadding/InvalidKey/InvalidAlgorithmParameter, itd.)
            System.err.println("Error: " + e.getMessage());
            // Ako u StatusCode postoji DECRYPTION_ERROR, koristi njega umesto ENCRYPTION_ERROR:
            // return StatusCode.DECRYPTION_ERROR;
            return StatusCode.ENCRYPTION_ERROR;
        } finally {
            // (9) ZATVARANJE STREAM-A (ne zatvaramo System.out)
            try {
                if (out != null && out != System.out) out.close();
            } catch (IOException ignore) {}
        }
    }
}
