package assignment1.cli;

public class ArgumentBundle {
    private String inputPath;
    private String outputPath;

    private String cipher;
    private String ivPath;

    private String keyPath;
    private String password;
    private String saltPath;

    private String mode;

    // getter/setter za input
    public String getInputPath() {
        return inputPath;
    }

    public void setInputPath(String inputPath) {
        this.inputPath = inputPath;
    }

    public String getOutputPath() {
        return outputPath;
    }

    public void setOutputPath(String outputPath) {
        this.outputPath = outputPath;
    }

    // getter/setter za cipher
    public String getCipher() {
        return cipher;
    } // <-- NOVO

    public void setCipher(String cipher) {
        this.cipher = cipher;
    } // <-- NOVO

    // getter/setter za -iv
    public String getIvPath() {
        return ivPath;
    }

    public void setIvPath(String ivPath) {
        this.ivPath = ivPath;
    }

    // getter/setter keyPath/pass/salt
    public String getKeyPath() {
        return keyPath;
    }

    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSaltPath() {
        return saltPath;
    }

    public void setSaltPath(String saltPath) {
        this.saltPath = saltPath;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

}
