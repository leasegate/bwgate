package leasegate.bwgate;

/// A random password from letters, digits and a few symbols that survive shells and forms.
final class Generate {

    static final String CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%";

    static String password(int length) {
        if (length < 8 || length > 128) throw new IllegalArgumentException("a generated password is 8 to 128 characters");
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++) sb.append(CHARS.charAt(BwCrypto.RANDOM.nextInt(CHARS.length())));
        return sb.toString();
    }

    private Generate() {}
}
