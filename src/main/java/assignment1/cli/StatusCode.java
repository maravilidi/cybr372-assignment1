package assignment1.cli;

public class StatusCode {
    public static final int SUCCESS = 0;
    public static final int INVALID_ARGUMENTS = 1;
    public static final int FILE_NOT_FOUND = 2;
    public static final int FILE_NOT_READABLE = 3;
    public static final int FILE_WRITE_ERROR = 4;
    public static final int INVALID_KEY = 5;
    public static final int INVALID_IV = 6;
    public static final int INVALID_SALT = 7;
    public static final int UNSUPPORTED_CIPHER = 8;
    public static final int ENCRYPTION_ERROR = 9;
    public static final int DECRYPTION_ERROR = 10;
    public static final int UNKNOWN_ERROR = 99;

    private StatusCode() {}
}
