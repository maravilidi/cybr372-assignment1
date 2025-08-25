package assignment1;

import assignment1.cli.CLIApplication;
import assignment1.cli.StatusCode;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

import java.util.stream.Stream;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import java.security.SecureRandom;

class CLIApplicationTest {

    static final Path RESOURCES = Paths.get("src/test/resources");
    static final Path INPUT = RESOURCES.resolve("plaintext.txt");
    static final Path IV = RESOURCES.resolve("ivs/iv.base64");
    static final Path SALT = RESOURCES.resolve("salts/salt.base64");
    static final Path KEYS_DIR = RESOURCES.resolve("keys");
    static final Path EXPECTED_DIR = RESOURCES.resolve("expected_ciphertext");

    static Path tempOutputFile;
    private final List<Path> tempFilesToDelete = new ArrayList<>();

    @AfterEach
    void cleanupTempFiles() throws IOException {
        if (tempOutputFile != null && Files.exists(tempOutputFile)) {
            Files.delete(tempOutputFile);
            tempOutputFile = null;
        }

        for (Path path : tempFilesToDelete) {
            try {
                if (Files.exists(path)) {
                    Files.delete(path);
                }
            } catch (IOException e) {
                System.err.println("Warning: Could not delete temp file: " + path + " (" + e.getMessage() + ")");
            }
        }
        tempFilesToDelete.clear();
    }

    static class TestCase {
        final int keyBits;
        final String mode;

        TestCase(int keyBits, String mode) {
            this.keyBits = keyBits;
            this.mode = mode;
        }

        String cipherName() {
            return "aes-" + keyBits + "-" + mode;
        }

        String expectedOutputFilefromKey() {
            return "aes_" + keyBits + "_" + mode + "_from_key.enc";
        }

        String expectedOutputFilefromPassword() {
            return "aes_" + keyBits + "_" + mode + "_from_password.enc";
        }

        String keyFile() {
            return "key_" + keyBits + ".base64";
        }

        @Override
        public String toString() {
            return cipherName();
        }
    }

    static Stream<TestCase> provideEncryptionCases() {
        String[] modes = { "cbc", "cfb", "ctr", "ecb", "gcm", "ofb" };
        int[] keyLengths = { 128, 192, 256 };

        return Arrays.stream(keyLengths)
                .boxed()
                .flatMap(bits -> Stream.of(modes).map(mode -> new TestCase(bits, mode)));
    }

    // Utility to create a temporary file containing Base64-encoded bytes.
    // Used for generating test inputs like truncated keys/IVs/salts.
    // Overload 1: Takes number of bytes, generates random data
    private Path createBase64EncodedTempFile(int numBytes, String prefix, String suffix) throws IOException {
        byte[] data = new byte[numBytes];
        new SecureRandom().nextBytes(data);
        return createBase64EncodedTempFile(data, prefix, suffix);  // reuses Overload 2
    }

    // Overload 2: Takes the actual byte[] to encode and write
    private Path createBase64EncodedTempFile(byte[] data, String prefix, String suffix) throws IOException {
        Path path = Files.createTempFile(prefix, suffix);
        Files.write(path, Base64.getEncoder().encode(data));
        tempFilesToDelete.add(path);
        return path;
    }

    static Path createTempFileWithBytes(String prefix, String suffix, byte[] content) throws IOException {
        Path file = Files.createTempFile(prefix, suffix);
        Files.write(file, content);
        return file;
    }
    

    @ParameterizedTest(name = "{0} encryption with key")
    @MethodSource("provideEncryptionCases")
    void testEncryption(TestCase testCase) throws IOException {
        tempOutputFile = Files.createTempFile("test-", ".enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve(testCase.keyFile()).toString(),
            "-iv", IV.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "CLIApplication did not return SUCCESS");

        Path expectedPath = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromKey());
        long mismatchPos = Files.mismatch(expectedPath, tempOutputFile);

        assertEquals(-1, mismatchPos,
            () -> String.format("Mismatch at byte %d for %s", mismatchPos, testCase.cipherName()));
    }

    @ParameterizedTest(name = "{0} decryption with key")
    @MethodSource("provideEncryptionCases")
    void testDecryption(TestCase testCase) throws IOException {
        tempOutputFile = Files.createTempFile("dec-", ".txt");

        String[] argv = {
            "dec",
            "-in", EXPECTED_DIR.resolve(testCase.expectedOutputFilefromKey()).toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve(testCase.keyFile()).toString(),
            "-iv", IV.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "CLIApplication decryption did not return SUCCESS");

        long mismatch = Files.mismatch(INPUT, tempOutputFile);
        assertEquals(-1, mismatch,
            () -> String.format("Decryption mismatch at byte %d for %s", mismatch, testCase.cipherName()));
    }

    @ParameterizedTest(name = "{0} encryption with password")
    @MethodSource("provideEncryptionCases")
    void testPasswordEncryption(TestCase testCase) throws IOException {
        tempOutputFile = Files.createTempFile("encpass-", ".enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "secret123",
            "-salt", SALT.toString(),
            "-iv", IV.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "Password-based encryption failed for " + testCase);

        Path expectedPath = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromPassword());
        long mismatch = Files.mismatch(expectedPath, tempOutputFile);

        assertEquals(-1, mismatch,
            () -> String.format("Password-based encryption mismatch at byte %d for %s", mismatch, testCase));
    }

    @ParameterizedTest(name = "{0} decryption with password")
    @MethodSource("provideEncryptionCases")
    void testPasswordDecryption(TestCase testCase) throws IOException {
        tempOutputFile = Files.createTempFile("decpass-", ".txt");

        String[] argv = {
            "dec",
            "-in", EXPECTED_DIR.resolve(testCase.expectedOutputFilefromPassword()).toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "secret123",
            "-salt", SALT.toString(),
            "-iv", IV.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "Password-based decryption failed for " + testCase);

        long mismatch = Files.mismatch(INPUT, tempOutputFile);
        assertEquals(-1, mismatch,
            () -> String.format("Password-based decryption mismatch at byte %d for %s", mismatch, testCase));
    }

    @Test
    void testDefaultCipherIsUsed() throws IOException {
        Path expected = Files.createTempFile("expected-", ".enc");
        Path actual = Files.createTempFile("actual-", ".enc");

        String[] withExplicitCipher = {
            "enc",
            "-in", INPUT.toString(),
            "-out", expected.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String[] withDefaultCipher = {
            "enc",
            "-in", INPUT.toString(),
            "-out", actual.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString()
            // no -cipher
        };

        assertEquals(StatusCode.SUCCESS, CLIApplication.run(withExplicitCipher));
        assertEquals(StatusCode.SUCCESS, CLIApplication.run(withDefaultCipher));

        assertEquals(-1, Files.mismatch(expected, actual),
            "Default cipher aes-256-cbc did not match explicitly specified one.");
    }

    @Test
    void testDefaultOutputToStdout() throws IOException {
        Path expected = Files.createTempFile("expected-", ".enc");

        String[] withOutputFile = {
            "enc",
            "-in", INPUT.toString(),
            "-out", expected.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        assertEquals(StatusCode.SUCCESS, CLIApplication.run(withOutputFile));

        // Redirect stdout
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        System.setOut(new PrintStream(stdout));

        String[] toStdout = {
            "enc",
            "-in", INPUT.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        assertEquals(StatusCode.SUCCESS, CLIApplication.run(toStdout));
        System.setOut(originalOut);

        byte[] expectedBytes = Files.readAllBytes(expected);
        byte[] actualBytes = stdout.toByteArray();

        assertArrayEquals(expectedBytes, actualBytes, "Ciphertext from stdout does not match expected output file.");
    }

    static Stream<TestCase> provideSubsetForFlagOrder() {
        return Stream.of(
            new TestCase(128, "cbc"),
            new TestCase(192, "ctr"),
            new TestCase(256, "gcm")
        );
    }

    @ParameterizedTest(name = "Flag order should not affect encryption for {0}")
    @MethodSource("provideSubsetForFlagOrder")
    void testEncryptionFlagOrderInvariance(TestCase testCase) throws IOException {
        Path expectedPath = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromKey());
    
        for (int i = 0; i < argumentPermutations(testCase).length; i++) {
            tempOutputFile = Files.createTempFile("flag-order-", ".enc");
    
            String[] baseArgs = argumentPermutations(testCase)[i];
            String[] argv = appendOutArg(baseArgs, tempOutputFile.toString());
    
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.SUCCESS, result, "CLIApplication failed for permutation #" + (i + 1));
    
            long mismatch = Files.mismatch(expectedPath, tempOutputFile);
            final long finalMismatch = mismatch;
            final int permutationIndex = i + 1;
    
            assertEquals(-1, finalMismatch,
                () -> String.format("Flag order mismatch at byte %d for %s (permutation #%d)",
                    finalMismatch, testCase.cipherName(), permutationIndex));
        }
    }
    

    private String[][] argumentPermutations(TestCase testCase) {
        String key = KEYS_DIR.resolve(testCase.keyFile()).toString();
        String iv = IV.toString();
        String in = INPUT.toString();
        String cipher = testCase.cipherName();
    
        return new String[][] {
            {"enc", "-cipher", cipher, "-key", key, "-iv", iv, "-in", in},
            {"enc", "-in", in, "-cipher", cipher, "-iv", iv, "-key", key},
            {"enc", "-iv", iv, "-key", key, "-cipher", cipher, "-in", in}
        };
    }
    
    private String[] appendOutArg(String[] args, String outPath) {
        String[] extended = Arrays.copyOf(args, args.length + 2);
        extended[args.length] = "-out";
        extended[args.length + 1] = outPath;
        return extended;
    }
    
    @ParameterizedTest(name = "Flag order should not affect the decryption for {0}")
    @MethodSource("provideSubsetForFlagOrder")
    void testDecryptionFlagOrderInvariance(TestCase testCase) throws IOException {
        Path expectedPlaintext = INPUT;
    
        for (int i = 0; i < decryptionArgumentPermutations(testCase).length; i++) {
            tempOutputFile = Files.createTempFile("flag-order-dec-", ".txt");
    
            String[] baseArgs = decryptionArgumentPermutations(testCase)[i];
            String[] argv = appendOutArg(baseArgs, tempOutputFile.toString());
    
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.SUCCESS, result, "Decryption failed for flag permutation #" + (i + 1));
    
            long mismatch = Files.mismatch(expectedPlaintext, tempOutputFile);
            final long finalMismatch = mismatch;
            final int permutationIndex = i + 1;
    
            assertEquals(-1, finalMismatch,
                () -> String.format("Decryption mismatch at byte %d for %s (permutation #%d)",
                    finalMismatch, testCase.cipherName(), permutationIndex));
        }
    }
   
    private String[][] decryptionArgumentPermutations(TestCase testCase) {
        String key = KEYS_DIR.resolve(testCase.keyFile()).toString();
        String iv = IV.toString();
        String in = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromKey()).toString();
        String cipher = testCase.cipherName();
    
        return new String[][] {
            {"dec", "-cipher", cipher, "-key", key, "-iv", iv, "-in", in},
            {"dec", "-in", in, "-cipher", cipher, "-iv", iv, "-key", key},
            {"dec", "-iv", iv, "-key", key, "-cipher", cipher, "-in", in}
        };
    }

    @Test
    void testKeyTakesPrecedenceOverPassword() throws IOException {
        tempOutputFile = Files.createTempFile("enc-key-priority-", ".enc");
    
        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-cipher", "aes-256-cbc",
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-password", "yumyumbaronies",
            "-salt", RESOURCES.resolve("salts/salt.base64").toString(),
            "-iv", IV.toString()
        };
    
        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "Encryption failed");
    
        Path expectedPath = EXPECTED_DIR.resolve("aes_256_cbc_from_key.enc");
        long mismatch = Files.mismatch(expectedPath, tempOutputFile);
    
        assertEquals(-1, mismatch, "Output does not match expected (key should take precedence over password)");
    }
    

    @Test
    void testEmptyPlaintextEncryptionAndDecryption() throws IOException {
        Path emptyFile = Files.createTempFile("empty-", ".txt");
        Path encryptedOutput = Files.createTempFile("empty-encrypted-", ".enc");
        Path decryptedOutput = Files.createTempFile("empty-decrypted-", ".txt");

        try {
            String[] encArgs = {
                "enc",
                "-in", emptyFile.toString(),
                "-out", encryptedOutput.toString(),
                "-cipher", "aes-256-cbc",
                "-key", KEYS_DIR.resolve("key_256.base64").toString(),
                "-iv", IV.toString()
            };

            int encResult = CLIApplication.run(encArgs);
            assertEquals(StatusCode.SUCCESS, encResult, "Encryption of empty input failed");

            String[] decArgs = {
                "dec",
                "-in", encryptedOutput.toString(),
                "-out", decryptedOutput.toString(),
                "-cipher", "aes-256-cbc",
                "-key", KEYS_DIR.resolve("key_256.base64").toString(),
                "-iv", IV.toString()
            };

            int decResult = CLIApplication.run(decArgs);
            assertEquals(StatusCode.SUCCESS, decResult, "Decryption of empty ciphertext failed");

            assertEquals(0, Files.size(decryptedOutput), "Decrypted output should be empty");

        } finally {
            Files.deleteIfExists(emptyFile);
            Files.deleteIfExists(encryptedOutput);
            Files.deleteIfExists(decryptedOutput);
        }
    }

    @Test
    void testEncryptionOutputFileIsOverwritten() throws IOException {
        tempOutputFile = Files.createTempFile("overwrite-test-", ".enc");
    
        // Step 1: Write dummy content to simulate a pre-existing file
        byte[] dummyContent = "THIS IS GARBAGE".getBytes(StandardCharsets.UTF_8);
        Files.write(tempOutputFile, dummyContent);
    
        // Step 2: Run encryption with -out pointing to the existing file
        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString()
            // cipher not provided → default to aes-256-cbc
        };
    
        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "Encryption failed when overwriting existing output file");
    
        // Step 3: Ensure the file content was changed (i.e., overwritten)
        byte[] actualContent = Files.readAllBytes(tempOutputFile);
        assertFalse(Arrays.equals(dummyContent, actualContent), "Output file was not overwritten as expected");
    }

    @Test
    void testDecryptionOutputFileIsOverwritten() throws IOException {
        // Use pre-encrypted ciphertext with aes-256-cbc
        Path encryptedInput = EXPECTED_DIR.resolve("aes_256_cbc_from_key.enc");
        tempOutputFile = Files.createTempFile("overwrite-dec-test-", ".txt");
    
        // Step 1: Write dummy content to simulate a pre-existing file
        byte[] dummyContent = "GARBAGE OUTPUT".getBytes(StandardCharsets.UTF_8);
        Files.write(tempOutputFile, dummyContent);
    
        // Step 2: Run decryption with -out pointing to the existing file
        String[] argv = {
            "dec",
            "-in", encryptedInput.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString()
            // cipher not provided → default to aes-256-cbc
        };
    
        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result, "Decryption failed when overwriting existing output file");
    
        // Step 3: Check that output is different from the dummy and matches expected plaintext
        byte[] actualContent = Files.readAllBytes(tempOutputFile);
        assertFalse(Arrays.equals(dummyContent, actualContent), "Decryption output file was not overwritten");
    
        long mismatch = Files.mismatch(INPUT, tempOutputFile);
        assertEquals(-1, mismatch, "Decryption result does not match original plaintext");
    }

    // Finally, for happy paths, round-trip tests:
    // encrypt -> decrypt -> verify original plaintext for random plaintext and parameters
    @ParameterizedTest(name = "Round-trip encryption-decryption for {0}")
    @MethodSource("provideEncryptionCases")
    void testEncryptionDecryptionRoundTrip(TestCase testCase) throws Exception {
        // Generate random plaintext
        byte[] plaintext = new byte[128];
        new SecureRandom().nextBytes(plaintext);
        Path inputFile = createTempFileWithBytes("roundtrip-input-", ".bin", plaintext);
        tempFilesToDelete.add(inputFile);

        Path encryptedFile = Files.createTempFile("roundtrip-enc-", ".bin");
        Path decryptedFile = Files.createTempFile("roundtrip-dec-", ".bin");
        tempFilesToDelete.addAll(List.of(encryptedFile, decryptedFile));

        // Create key file
        Path keyFile = createBase64EncodedTempFile(testCase.keyBits / 8, "roundtrip-key-", ".base64");

        // Optional IV file
        Path ivFile = null;
        if (!testCase.mode.equalsIgnoreCase("ecb")) {
            ivFile = createBase64EncodedTempFile(16, "roundtrip-iv-", ".base64"); // AES block size
        }

        // --- Encrypt ---
        List<String> encArgs = new ArrayList<>(List.of(
            "enc",
            "-in", inputFile.toString(),
            "-out", encryptedFile.toString(),
            "-key", keyFile.toString(),
            "-cipher", testCase.cipherName()
        ));
        if (ivFile != null) {
            encArgs.add("-iv");
            encArgs.add(ivFile.toString());
        }

        int encResult = CLIApplication.run(encArgs.toArray(new String[0]));
        assertEquals(StatusCode.SUCCESS, encResult, "Encryption failed for: " + testCase);

        // --- Decrypt ---
        List<String> decArgs = new ArrayList<>(List.of(
            "dec",
            "-in", encryptedFile.toString(),
            "-out", decryptedFile.toString(),
            "-key", keyFile.toString(),
            "-cipher", testCase.cipherName()
        ));
        if (ivFile != null) {
            decArgs.add("-iv");
            decArgs.add(ivFile.toString());
        }

        int decResult = CLIApplication.run(decArgs.toArray(new String[0]));
        assertEquals(StatusCode.SUCCESS, decResult, "Decryption failed for: " + testCase);

        // --- Verify ---
        byte[] decrypted = Files.readAllBytes(decryptedFile);
        assertArrayEquals(plaintext, decrypted, "Round-trip mismatch for: " + testCase);
    }

    // ERROR CASES NOW!
    @Test
    void testInvalidOperation() throws IOException {
        tempOutputFile = Files.createTempFile("invalid-op-", ".enc");  // Assign to tempOutputFile for auto cleanup
    
        String[] argv = {
            "encrypt",  // Invalid operation, must be "enc" or "dec"
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };
    
        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.INVALID_ARGUMENTS, result, "Invalid operation should result in INVALID_OPERATION");
    }

    // Missing Mandatory Parameters

    private String captureStderr(Runnable runnable) {
        PrintStream originalErr = System.err;
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));
        try {
            runnable.run();
        } finally {
            System.setErr(originalErr);
        }
        return errContent.toString();
    }

    @Test
    void testMissingInputFile() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_ARGUMENTS, result);
        });

        assertTrue(err.toLowerCase().contains("input"), "Error should mention missing input");
    }

    @Test
    void testMissingKey() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_ARGUMENTS, result);
        });

        assertTrue(err.toLowerCase().contains("key"), "Error should mention missing key");
    }

    @Test
    void testMissingSaltWithPassword() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "mypassword",
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
            // salt missing intentionally
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_ARGUMENTS, result);
        });

        assertTrue(err.toLowerCase().contains("salt"), "Error should mention missing salt");
    }

    @Test
    void testMissingIvWhenRequired() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-cipher", "aes-256-cbc"
            // iv missing
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_ARGUMENTS, result);
        });

        assertTrue(err.toLowerCase().contains("iv"), "Error should mention missing iv");
    }

    @Test
    void testNoIvNeededForEcb() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-cipher", "aes-256-ecb"
            // iv intentionally missing
        };

        int result = CLIApplication.run(argv);
        assertEquals(StatusCode.SUCCESS, result);
    }

    @Test
    void testInputFileDoesNotExist() {
        tempOutputFile = Path.of("someoutput.enc");  

        String[] argv = {
            "enc",
            "-in", "nonexistent-input.txt",
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.FILE_NOT_FOUND, result);
        });

        assertTrue(err.toLowerCase().contains("input"), "Error should mention input file issue");
    }

    @Test
    void testKeyFileDoesNotExist() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", "nonexistent-key.base64",
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.FILE_NOT_FOUND, result);
        });

        assertTrue(err.toLowerCase().contains("key"), "Error should mention key file issue");
    }

    @Test
    void testIvFileDoesNotExist() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", "nonexistent-iv.txt",
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.FILE_NOT_FOUND, result);
        });

        assertTrue(err.toLowerCase().contains("iv"), "Error should mention iv file issue");
    }


    @Test
    void testSaltFileDoesNotExist() {
        tempOutputFile = Path.of("someoutput.enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "mypass",
            "-salt", "nonexistent-salt.base64",
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.FILE_NOT_FOUND, result);
        });

        assertTrue(err.toLowerCase().contains("salt"), "Error should mention salt file issue");
    }

    // // Output path is in a directory which is not writable to.
    // // Expect FILE_WRITE_ERROR.
    // @Test
    // void testUnwritableOutputDirectory() throws IOException {
    //     Path dir = Files.createTempDirectory("readonly-dir");
    //     Path tempOutputFile = dir.resolve("out.enc");
    
    //     try {
    //         // Make the directory read-only
    //         dir.toFile().setWritable(false);
    
    //         String[] argv = {
    //             "enc",
    //             "-in", INPUT.toString(),
    //             "-out", tempOutputFile.toString(),
    //             "-key", KEYS_DIR.resolve("key_256.base64").toString(),
    //             "-iv", IV.toString()
    //         };
    
    //         String stderr = captureStderr(() -> {
    //             int result = CLIApplication.run(argv);
    //             assertEquals(StatusCode.FILE_WRITE_ERROR, result);
    //         });
    
    //         assertTrue(
    //             stderr.toLowerCase().contains("writ") || stderr.toLowerCase().contains("permission"),
    //             "Expected an error message about write permissions"
    //         );
    
    //     } finally {
    //         // Restore permissions so the directory can be cleaned up
    //         dir.toFile().setWritable(true);
    //         Files.deleteIfExists(dir);
    //     }
    // }
    
    // Output path points to a directory, which is not writable as a file.
    // Expect FILE_WRITE_ERROR.
    @Test
    void testOutputPathIsDirectory() throws IOException {
        Path directory = Files.createTempDirectory("output-is-dir");
    
        try {
            String[] argv = {
                "enc",
                "-in", INPUT.toString(),
                "-out", directory.toString(),  // Trying to write to a directory
                "-key", KEYS_DIR.resolve("key_256.base64").toString(),
                "-iv", IV.toString()
            };
    
            String stderr = captureStderr(() -> {
                int result = CLIApplication.run(argv);
                assertEquals(StatusCode.FILE_WRITE_ERROR, result);
            });
    
            assertTrue(
                stderr.toLowerCase().contains("directory") || stderr.toLowerCase().contains("writ"),
                "Expected error about output path being a directory"
            );
        } finally {
            Files.deleteIfExists(directory);
        }
    }

    // Output path contains a non-existent directory.
    // Expect FILE_WRITE_ERROR.
    @Test
    void testOutputInNonexistentDirectory() throws IOException {
        Path outputPath = Paths.get("nonexistent-dir", "file.enc");
        try {
            String[] argv = {
                "enc",
                "-in", INPUT.toString(),
                "-out", outputPath.toString(),
                "-key", KEYS_DIR.resolve("key_256.base64").toString(),
                "-iv", IV.toString()
            };

            String stderr = captureStderr(() -> {
                int result = CLIApplication.run(argv);
                assertEquals(StatusCode.FILE_WRITE_ERROR, result);
            });

            assertTrue(stderr.toLowerCase().contains("exist") || stderr.toLowerCase().contains("writ"));
        } finally {
            Files.deleteIfExists(outputPath);
        }
    }
    
    // @Test
    // void testUnreadableInputFile() throws IOException {
    //     Path unreadableFile = Files.createTempFile("unreadable-input-", ".txt");
    //     Path outputFile = Files.createTempFile("should-not-be-written-", ".enc");
    
    //     try {
    //         Files.writeString(unreadableFile, "This file exists but is unreadable.");
    //         unreadableFile.toFile().setReadable(false);  // Make unreadable
    
    //         String[] argv = {
    //             "enc",
    //             "-in", unreadableFile.toString(),
    //             "-out", outputFile.toString(),
    //             "-key", KEYS_DIR.resolve("key_256.base64").toString(),
    //             "-iv", IV.toString()
    //         };
    
    //         String stderr = captureStderr(() -> {
    //             int result = CLIApplication.run(argv);
    //             assertEquals(StatusCode.FILE_NOT_READABLE, result);  // Prefer FILE_NOT_READABLE over FILE_NOT_FOUND
    //         });
    
    //         assertTrue(stderr.toLowerCase().contains("file") || stderr.toLowerCase().contains("read"),
    //                 "Error message should indicate unreadable input file");
    
    //     } finally {
    //         // Restore permissions before deletion
    //         unreadableFile.toFile().setReadable(true);
    //         Files.deleteIfExists(unreadableFile);
    //         Files.deleteIfExists(outputFile);
    //     }
    // }
    

    // Key file contains invalid Base64 content. Expect decoding failure.
    @Test
    void testMalformedKeyNotBase64() throws IOException {
        tempOutputFile = Files.createTempFile("bad-key-out-", ".enc");
        Path badKeyFile = Files.createTempFile("bad-key-", ".base64");        
        tempFilesToDelete.add(badKeyFile);

        // Write malformed (non-base64) key
        Files.writeString(badKeyFile, "!!!not-base64@@@");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", badKeyFile.toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_KEY, result);
        });

        assertTrue(err.toLowerCase().contains("key"), "Error should mention malformed key");
    }

    // Key file contains Base64 content of incorrect length for AES-256.
    // Expect failure due to key size mismatch.
    @Test
    void testMalformedKeyWrongLength() throws IOException {
        tempOutputFile = Files.createTempFile("bad-key-len-out-", ".enc");
        Path badKey = createBase64EncodedTempFile(10, "bad-key-", ".base64"); // 10 bytes too short for AES-256

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", badKey.toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_KEY, result);
        });

        assertTrue(err.toLowerCase().contains("key"), "Error should mention key length");
    }

    // IV file contains invalid Base64 content. Expect decoding failure.
    @Test
    void testMalformedIvNotBase64() throws IOException {
        tempOutputFile = Files.createTempFile("bad-iv-out-", ".enc");
        Path badIv = Files.createTempFile("bad-iv-", ".base64");
        Files.writeString(badIv, "000@@!!notbase64");
        tempFilesToDelete.add(badIv);

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", badIv.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_IV, result);
        });

        assertTrue(err.toLowerCase().contains("iv"), "Error should mention malformed IV");
    }

    // IV file is valid Base64 but decoded to wrong size (too short).
    // Should trigger a validation error.
    @Test
    void testMalformedIvWrongLength() throws IOException {
        tempOutputFile = Files.createTempFile("bad-iv-len-out-", ".enc");
        Path badIV = createBase64EncodedTempFile(5, "bad-iv-len-", ".base64"); // IV needs to be 16 bytes long for AES

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", badIV.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_IV, result);
        });

        assertTrue(err.toLowerCase().contains("iv"), "Error should mention IV length");
    }

    // Salt file contains invalid Base64 input. Should not decode successfully.
    @Test
    void testMalformedSaltNotBase64() throws IOException {
        tempOutputFile = Files.createTempFile("bad-salt-out-", ".enc");
        Path badSalt = Files.createTempFile("bad-salt-", ".base64");

        Files.writeString(badSalt, "!!!not-a-valid-base64$$$");
        tempFilesToDelete.add(badSalt);

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "testpassword",
            "-salt", badSalt.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_SALT, result);
        });

        assertTrue(err.toLowerCase().contains("salt"), "Error should mention malformed salt");
    }

    // Salt file is valid Base64 but the decoded salt has the wrong length.
    @Test
    void testMalformedSaltWrongLength() throws IOException {
        tempOutputFile = Files.createTempFile("bad-salt-len-out-", ".enc");
        Path badSalt = createBase64EncodedTempFile(4, "bad-salt-len-", ".base64"); // 4 bytes is too short, salt needs to be 8+ bytes

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "testpassword",
            "-salt", badSalt.toString(),
            "-cipher", "aes-256-cbc"
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.INVALID_SALT, result);
        });

        assertTrue(err.toLowerCase().contains("salt"), "Error should mention salt length");
    }

    // Cipher is not recognized by the application. Should return UNSUPPORTED_CIPHER.
    @Test
    void testUnsupportedCipher() throws IOException {
        tempOutputFile = Files.createTempFile("invalid-cipher-out-", ".enc");

        String[] argv = {
            "enc",
            "-in", INPUT.toString(),
            "-out", tempOutputFile.toString(),
            "-cipher", "aes-256-xyz",
            "-key", KEYS_DIR.resolve("key_256.base64").toString(),
            "-iv", IV.toString()
        };

        String err = captureStderr(() -> {
            int result = CLIApplication.run(argv);
            assertEquals(StatusCode.UNSUPPORTED_CIPHER, result);
        });

        assertTrue(err.toLowerCase().contains("cipher"), "Error should mention unsupported cipher");
    }

    //  Test: Wrong Password Decrypts Without Error (No AEAD, No Padding)
    static Stream<TestCase> someCiphersWithoutPaddingAndAuthentication() {
        return Stream.of(
            new TestCase(256, "ctr"),
            new TestCase(192, "cfb"),
            new TestCase(256, "ofb")
            // omit GCM here
        );
    }

    // Decryption with a mismatched password. Should result in incorrect output.
    @ParameterizedTest(name = "Wrong password decryption should just yield incorrect plaintext for {0}")
    @MethodSource("someCiphersWithoutPaddingAndAuthentication")
    void testWrongPasswordDecryptsButWrongPlaintext(TestCase testCase) throws IOException {
        Path ciphertextFile = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromPassword());
        Path tempOutputFile = Files.createTempFile("wrong-pass-out-", ".dec");

        String[] argv = {
            "dec",
            "-in", ciphertextFile.toString(),
            "-out", tempOutputFile.toString(),
            "-pass", "incorrect_password",  // intentionally wrong
            "-iv", IV.toString(),
            "-salt", SALT.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);

        // Should not fail for CFB, OFB, CTR
        assertEquals(StatusCode.SUCCESS, result, "Decryption with wrong password should still succeed for " + testCase.cipherName());

        long mismatch = Files.mismatch(INPUT, tempOutputFile);
        assertNotEquals(-1, mismatch, "Wrong password should yield incorrect decryption output");
    }

    // Decryption with a mismatched key. Should result in incorrect output.
    @ParameterizedTest(name = "Wrong key decryption should just yield incorrect plaintext for {0}")
    @MethodSource("someCiphersWithoutPaddingAndAuthentication")
    void testWrongKeyDecryptsButWrongPlaintext(TestCase testCase) throws IOException {
        Path ciphertextFile = EXPECTED_DIR.resolve(testCase.expectedOutputFilefromKey());
        Path tempOutputFile = Files.createTempFile("wrong-key-out-", ".dec");
        Path wrongKeyFile = createBase64EncodedTempFile(testCase.keyBits/8, "wrong-key-", ".base64"); // required key length in number of bytes
        
        String[] argv = {
            "dec",
            "-in", ciphertextFile.toString(),
            "-out", tempOutputFile.toString(),
            "-key", wrongKeyFile.toString(),  // intentionally wrong
            "-iv", IV.toString(),
            "-cipher", testCase.cipherName()
        };

        int result = CLIApplication.run(argv);

        // // Should not fail for CFB, OFB, CTR
        assertEquals(StatusCode.SUCCESS, result, "Decryption with wrong key should still succeed for " + testCase.cipherName());

        long mismatch = Files.mismatch(INPUT, tempOutputFile);
        assertNotEquals(-1, mismatch, "Wrong key should yield incorrect decryption output");
    }

    // Wrong key used with AES-GCM mode.
    // Expect authentication failure (decryption error).
    @Test
    void testDecryptionWithWrongKeyGCM() throws IOException {
        // Wrong key (same length, random content)
        Path ciphertextFile = EXPECTED_DIR.resolve("aes_256_gcm_from_key.enc");
        Path wrongKeyFile = createBase64EncodedTempFile(32, "wrong-key-gcm-", ".base64"); 
        
        // Attempt decryption with wrong key
        Path tempOutputFile = Files.createTempFile("gcm-dec-wrongkey-out-", ".txt");
        String[] decryptArgs = {
            "dec",
            "-in", ciphertextFile.toString(),
            "-out", tempOutputFile.toString(),
            "-key", wrongKeyFile.toString(),
            "-iv", IV.toString(),
            "-cipher", "aes-256-gcm"
        };
        int result = CLIApplication.run(decryptArgs);
        assertEquals(StatusCode.DECRYPTION_ERROR, result);
    }

}
