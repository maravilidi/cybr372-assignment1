package assignment1;

import assignment1.cli.CLIApplication;

public class Assignment1 {
    public static void main(String[] args) {
        int status = CLIApplication.run(args);
        System.exit(status);
    }
}
