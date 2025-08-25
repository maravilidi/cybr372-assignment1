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

        // Do the logic of argument validation and preparing the argument for dispatch

        // --- Finally dispatch operation ---
        return StatusCode.UNKNOWN_ERROR;
    }

}
