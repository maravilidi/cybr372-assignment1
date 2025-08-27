package assignment1.cli;

import assignment1.crypto.Encryptor;
import assignment1.crypto.Decryptor;
import assignment1.crypto.CipherUtils;

public class CLIApplication {
    public static int run(String[] argv) {
        ArgumentBundle args;
        try {
            args = ArgumentParser.parse(argv);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return StatusCode.INVALID_ARGUMENTS;
        }

        // pokupi -out (ako parser nije setovao)
        String outPath = null;
        for (int i = 0; i + 1 < argv.length; i++) {
            if ("-out".equals(argv[i])) {
                outPath = argv[i + 1];
                break;
            }
        }
        if (outPath != null && !outPath.isBlank()) {
            args.setOutputPath(outPath);
        }

        // -in mora da postoji
        String inPath = args.getInputPath();
        if (inPath == null || inPath.isBlank()) {
            System.err.println("Error: -in is required");
            return StatusCode.INVALID_ARGUMENTS;
        }
        java.nio.file.Path in = java.nio.file.Path.of(inPath);
        if (!java.nio.file.Files.exists(in)) {
            System.err.println("Error: input file not found: " + inPath);
            return StatusCode.FILE_NOT_FOUND;
        }

        // -cipher (default ili validan)
        String cipher = args.getCipher();
        if (cipher == null || cipher.isBlank()) {
            cipher = "aes-256-cbc";
        } else {
            cipher = cipher.toLowerCase();
            if (!cipher.matches("^aes-(128|192|256)-(ecb|cbc|cfb|ofb|ctr|gcm)$")) {
                System.err.println("Error: unsupported cipher: " + cipher);
                return StatusCode.UNSUPPORTED_CIPHER; // 8
            }
        }
        args.setCipher(cipher);

        // IV potreban osim za ECB
        boolean needsIv = !cipher.endsWith("-ecb");
        if (needsIv) {
            String ivPath = args.getIvPath();
            if (ivPath == null || ivPath.isBlank()) {
                System.err.println("Error: -iv is required for " + cipher);
                return StatusCode.FILE_NOT_FOUND;
            }
            java.nio.file.Path iv = java.nio.file.Path.of(ivPath);
            if (!java.nio.file.Files.exists(iv)) {
                System.err.println("Error: IV file not found: " + ivPath);
                return StatusCode.FILE_NOT_FOUND;
            }
        }

        // KEY vs PASS (key ima prednost)
        String keyPath = args.getKeyPath();
        String password = args.getPassword();
        String saltPath = args.getSaltPath();

        if (keyPath != null && !keyPath.isBlank()) {
            java.nio.file.Path kp = java.nio.file.Path.of(keyPath);
            if (!java.nio.file.Files.exists(kp)) {
                System.err.println("Error: key file not found: " + keyPath);
                return StatusCode.FILE_NOT_FOUND;
            }
            args.setPassword(null);
            args.setSaltPath(null);
        } else if (password != null && !password.isBlank()) {
            if (saltPath == null || saltPath.isBlank()) {
                System.err.println("Error: -salt is required when -pass is provided");
                return StatusCode.INVALID_ARGUMENTS;
            }
            java.nio.file.Path sp = java.nio.file.Path.of(saltPath);
            if (!java.nio.file.Files.exists(sp)) {
                System.err.println("Error: salt file not found: " + saltPath);
                return StatusCode.FILE_NOT_FOUND;
            }
        } else {
            System.err.println("Error: either -key or -pass must be provided");
            return StatusCode.INVALID_ARGUMENTS;
        }

        // mode normalizacija
        String mode = args.getMode();
        if (mode == null && argv != null && argv.length > 0) {
            String m0 = argv[0].toLowerCase();
            if ("enc".equals(m0) || "dec".equals(m0))
                mode = m0;
        }
        if (!"enc".equals(mode) && !"dec".equals(mode)) {
            System.err.println("Error: you must specify enc or dec as the first argument");
            return StatusCode.INVALID_ARGUMENTS;
        }
        args.setMode(mode);

        // dispatch
        if ("enc".equals(mode))
            return Encryptor.run(args);
        if ("dec".equals(mode))
            return Decryptor.run(args);

        System.err.println("Error: you must specify enc or dec as the first argument");
        return StatusCode.INVALID_ARGUMENTS;
    }

}
