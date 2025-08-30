// package assignment1.cli;

// public class ArgumentParser {

//     public static ArgumentBundle parse(String[] args) {
//         ArgumentBundle bundle = new ArgumentBundle();

//         return bundle;
//     }
// }OVO JE ORIGINAL< ISPOD PISEM ZBOG PROVERE
package assignment1.cli;

public class ArgumentParser {

    public static ArgumentBundle parse(String[] args) {
        ArgumentBundle bundle = new ArgumentBundle();
        int start = 0;
        if (args != null && args.length > 0) {
            String first = args[0].toLowerCase();
            if ("enc".equals(first) || "dec".equals(first)) {
                bundle.setMode(first); // <<< sačuvaj enc/dec
                start = 1; // <<< preskoči ga u for-petlji
            }
        }

        for (int i = start; i < args.length; i++) {
            // -in (obavezno)
            if ("-in".equals(args[i]) && i + 1 < args.length) {
                bundle.setInputPath(args[++i]);
                continue;
            }

            // -cipher
            if ("-cipher".equals(args[i])) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing value for -cipher");
                }
                bundle.setCipher(args[++i]);
                continue;
            }
            if (args[i].startsWith("-cipher=")) {
                bundle.setCipher(args[i].substring("-cipher=".length()));
                continue;
            }

            // -iv
            if ("-iv".equals(args[i]) && i + 1 < args.length) {
                bundle.setIvPath(args[++i]);
                continue;
            }
            if (args[i].startsWith("-iv=")) {
                bundle.setIvPath(args[i].substring("-iv=".length()));
                continue;
            }

            // -key (fajl)
            if ("-key".equals(args[i]) && i + 1 < args.length) {
                bundle.setKeyPath(args[++i]);
                continue;
            }
            if (args[i].startsWith("-key=")) {
                bundle.setKeyPath(args[i].substring("-key=".length()));
                continue;
            }

            // -pass (lozinka kao string)
            if ("-pass".equals(args[i]) && i + 1 < args.length) {
                bundle.setPassword(args[++i]);
                continue;
            }
            if (args[i].startsWith("-pass=")) {
                bundle.setPassword(args[i].substring("-pass=".length()));
                continue;
            }

            // -salt (fajl)
            if ("-salt".equals(args[i]) && i + 1 < args.length) {
                bundle.setSaltPath(args[++i]);
                continue;
            }
            if (args[i].startsWith("-salt=")) {
                bundle.setSaltPath(args[i].substring("-salt=".length()));
                continue;
            }
        }

        return bundle;
    }
}
