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

            // 4. UČITAJ KLJUČ ILI GA IZVEDI IZ LOZINKE (PBKDF2)
            //
            // U ovom koraku podržavamo dve putanje:
            // -key → ključ iz Base64 fajla (16/24/32 bajta)
            // -pass + -salt → derivacija PBKDF2WithHmacSHA256 (65536 iteracija)
            //
            // Napomena: potrebna dužina ključa zavisi od cipherSpec-a (aes-128/192/256).
            int requiredKeyBits;
            try {
                // primer: "aes-256-cbc" → parts[1] = "256"
                String[] p = cipherSpec.split("-");
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
                // → Putanja sa ključem ima PREDNOST nad lozinkom
                try {
                    byte[] b64 = Files.readAllBytes(java.nio.file.Path.of(keyPathStr));
                    keyBytes = java.util.Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 key");
                    return StatusCode.INVALID_KEY;
                } catch (IOException ioe) {
                    System.err.println("Error: key file not found: " + keyPathStr);
                    return StatusCode.FILE_NOT_FOUND;
                }

                int bits = keyBytes.length * 8;
                if (bits != 128 && bits != 192 && bits != 256) {
                    System.err.println("Error: invalid key length");
                    return StatusCode.INVALID_KEY;
                }

            } else if (password != null && !password.isBlank()) {
                // → Derivacija iz lozinke: mora postojati -salt fajl (Base64, tačno 8 bajtova)
                if (saltPath == null || saltPath.isBlank()) {
                    System.err.println("Error: -salt is required when -pass is provided");
                    return StatusCode.INVALID_ARGUMENTS;
                }

                byte[] saltBytes;
                try {
                    byte[] b64 = Files.readAllBytes(java.nio.file.Path.of(saltPath));
                    saltBytes = java.util.Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 salt");
                    return StatusCode.INVALID_SALT;
                } catch (IOException ioe) {
                    System.err.println("Error: salt file not found: " + saltPath);
                    return StatusCode.FILE_NOT_FOUND;
                }

                // specifikacija zadatka: 8-bajtni salt
                if (saltBytes.length != 8) {
                    System.err.println("Error: salt must be 8 bytes");
                    return StatusCode.INVALID_SALT;
                }

                try {
                    // PBKDF2WithHmacSHA256, 65536 iteracija, output dužine requiredKeyBits
                    javax.crypto.SecretKeyFactory skf = javax.crypto.SecretKeyFactory
                            .getInstance("PBKDF2WithHmacSHA256");
                    javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(),
                            saltBytes, 65536, requiredKeyBits);
                    keyBytes = skf.generateSecret(spec).getEncoded();
                } catch (Exception e) {
                    System.err.println("Error: key derivation failed");
                    return StatusCode.ENCRYPTION_ERROR;
                }

            } else {
                // ni -key ni -pass
                System.err.println("Error: either -key or -pass must be provided");
                return StatusCode.INVALID_ARGUMENTS;
            }

            // 5. UČITAJ IV samo ako je potreban (ECB ne traži IV)
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
                    // pokušaćemo da pročitamo fajl; ako ne postoji → FILE_NOT_FOUND (2)
                    ivB64 = Files.readAllBytes(java.nio.file.Path.of(ivPathStr));
                } catch (IOException ioe) {
                    System.err.println("Error: IV file not found: " + ivPathStr);
                    return StatusCode.FILE_NOT_FOUND;
                }

                try {
                    // IV u fajlu je Base64; ako je neispravan → INVALID_IV (6)
                    ivBytes = java.util.Base64.getDecoder().decode(ivB64);
                } catch (IllegalArgumentException e) {
                    System.err.println("Error: invalid base64 iv");
                    return StatusCode.INVALID_IV;
                }

                // (za sada) validacija dužine IV = 16 bajtova (CBC/CFB/OFB/CTR); GCM ćemo
                // dodati kasnije
                if (ivBytes.length != 16) {
                    System.err.println("Error: IV must be 16 bytes for AES");
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
