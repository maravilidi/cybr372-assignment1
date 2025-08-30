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
            // Ako fajl ne postoji, uhvatićemo NoSuchFileException niže i vratiti
            // FILE_NOT_FOUND.
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
            if (cipherSpec == null || cipherSpec.isBlank())
                cipherSpec = "aes-256-cbc";
            cipherSpec = cipherSpec.toLowerCase();

            // Očekivani format: "aes-<128|192|256>-<ecb|cbc|...>"
            String[] parts = cipherSpec.split("-");
            if (parts.length != 3) {
                System.err.println("Error: unsupported cipher: " + cipherSpec);
                return StatusCode.UNSUPPORTED_CIPHER;
            }

            String mode = parts[2]; // ecb ili cbc (za sada)
            String transformation; // JCE transformacija
            boolean requiresIv; // da li je potreban IV

            switch (mode) {
                case "ecb":
                    // ECB ne koristi IV; koristi PKCS5 padding (PKCS7 u JCE terminologiji)
                    transformation = "AES/ECB/PKCS5Padding";
                    requiresIv = false;
                    break;

                case "cbc":
                    // CBC zahteva IV dužine 16 bajtova; takođe koristi PKCS5Padding
                    transformation = "AES/CBC/PKCS5Padding";
                    requiresIv = true;
                    break;

                case "ctr":
                    // CTR je strim-mod: nema padding (NoPadding), ali i dalje traži IV/nonce od 16
                    // bajtova
                    // Napomena: u našem kodu ispod već postoji provera dužine IV=16 kada
                    // requiresIv==true
                    transformation = "AES/CTR/NoPadding";
                    requiresIv = true;
                    break;

                default:
                    // Za sve ostale modove (cfb/ofb/gcm) za sada prijavi da nije podržano
                    System.err.println("Error: unsupported cipher mode: " + mode);
                    return StatusCode.UNSUPPORTED_CIPHER;
            }

            // (4) UČITAVANJE KLJUČA IZ FAJLA (Base64)
            // (4) KLJUČ: ili iz fajla (-key) ili derivacija iz lozinke (-pass + -salt,
            // PBKDF2)
            //
            // Prioritet:
            // - ako postoji -key → koristi njega (ignorisi -pass)
            // - inace ako postoji -pass → deriviraj PBKDF2WithHmacSHA256 (65536 iter.)
            // - u suprotnom → greska

            // Iz cipherSpec vadimo potrebnu duzinu kljuca (128/192/256 bita)
            int requiredKeyBits;
            try {
                String[] p = cipherSpec.split("-"); // npr. "aes-256-cbc" → ["aes","256","cbc"]
                requiredKeyBits = Integer.parseInt(p[1]); // 128/192/256
            } catch (Exception e) {
                System.err.println("Error: unsupported cipher: " + cipherSpec);
                return StatusCode.UNSUPPORTED_CIPHER;
            }

            byte[] keyBytes = null;
            String keyPathStr = args.getKeyPath();
            String password = args.getPassword();
            String saltPath = args.getSaltPath();

            if (keyPathStr != null && !keyPathStr.isBlank()) {
                // --- VARIJANTA A: kljuc iz Base64 fajla ---
                try {
                    byte[] b64 = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(keyPathStr));
                    keyBytes = java.util.Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException e) {
                    // Base64 decode propao → neispravan format
                    System.err.println("Error: invalid base64 key");
                    return StatusCode.INVALID_KEY;
                } catch (java.io.IOException ioe) {
                    // fajl ne postoji / nije čitljiv
                    System.err.println("Error: key file not found: " + keyPathStr);
                    return StatusCode.FILE_NOT_FOUND;
                }

                int bits = keyBytes.length * 8;
                if (bits != 128 && bits != 192 && bits != 256) {
                    System.err.println("Error: invalid key length");
                    return StatusCode.INVALID_KEY;
                }

            } else if (password != null && !password.isBlank()) {
                // --- VARIJANTA B: PBKDF2 iz lozinke ---
                // mora postojati -salt fajl (Base64) koji dekodiran ima TACNO 8 bajtova
                if (saltPath == null || saltPath.isBlank()) {
                    System.err.println("Error: -salt is required when -pass is provided");
                    return StatusCode.INVALID_ARGUMENTS;
                }

                byte[] saltBytes;
                try {
                    byte[] b64 = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(saltPath));
                    saltBytes = java.util.Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 salt");
                    return StatusCode.INVALID_SALT;
                } catch (java.io.IOException ioe) {
                    System.err.println("Error: salt file not found: " + saltPath);
                    return StatusCode.FILE_NOT_FOUND;
                }

                if (saltBytes.length != 8) {
                    System.err.println("Error: salt must be 8 bytes");
                    return StatusCode.INVALID_SALT;
                }

                try {
                    // PBKDF2WithHmacSHA256, 65536 iteracija, duzina = requiredKeyBits
                    javax.crypto.SecretKeyFactory skf = javax.crypto.SecretKeyFactory
                            .getInstance("PBKDF2WithHmacSHA256");
                    javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(),
                            saltBytes, 65536, requiredKeyBits);
                    keyBytes = skf.generateSecret(spec).getEncoded();
                } catch (Exception e) {
                    System.err.println("Error: key derivation failed");
                    // za dekripciju je prirodnije:
                    return StatusCode.DECRYPTION_ERROR;
                }

            } else {
                // ni -key ni -pass → nemamo kako do ključa
                System.err.println("Error: either -key or -pass must be provided");
                return StatusCode.INVALID_ARGUMENTS;
            }

            // (5) UČITAVANJE IV-A (ako je potreban)
            byte[] ivBytes = null;
            if (requiresIv) {
                String ivPathStr = args.getIvPath();
                if (ivPathStr == null || ivPathStr.isBlank()) {
                    // -iv obavezan za sve modove osim ECB
                    System.err.println("Error: -iv is required for " + cipherSpec);
                    return StatusCode.INVALID_ARGUMENTS;
                }

                byte[] ivB64;
                try {
                    // čitanje IV fajla; ako ne postoji → FILE_NOT_FOUND (2)
                    ivB64 = Files.readAllBytes(Path.of(ivPathStr));
                } catch (IOException ioe) {
                    System.err.println("Error: IV file not found: " + ivPathStr);
                    return StatusCode.FILE_NOT_FOUND;
                }

                try {
                    // Base64 dekodiranje IV-a; nevažeći sadržaj → INVALID_IV (6)
                    ivBytes = Base64.getDecoder().decode(ivB64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 iv");
                    return StatusCode.INVALID_IV;
                }

                // (za sada) očekujemo 16 bajtova (CBC/CFB/OFB/CTR); GCM ćemo posebno obraditi
                // kasnije
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

            // (7) DEKRIPCIJA (doFinal) — može baciti npr. BadPaddingException za pogrešan
            // ključ/IV
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
            return StatusCode.DECRYPTION_ERROR;
        } finally {
            // (9) ZATVARANJE STREAM-A (ne zatvaramo System.out)
            try {
                if (out != null && out != System.out) {
                    out.close();
                }
            } catch (IOException ignore) {
            }
        }
    }
}