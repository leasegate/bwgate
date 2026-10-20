package leasegate.bwgate;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import javax.crypto.Cipher;

import static leasegate.bwgate.BwCrypto.*;

/// Bitwarden's encrypted string: `2.<iv>|<ciphertext>|<mac>` (AES-256-CBC, HMAC-SHA256 over iv and
/// ciphertext, all base64) for everything in a vault, and `4.<data>` (RSA-OAEP-SHA1) for an
/// organisation's key sent to a member. The MAC is checked before anything is decrypted.
public final class EncString {

    public static byte[] decrypt(String s, SymKey key) {
        if (s == null) return null;
        var dot = s.indexOf('.');
        var type = s.substring(0, dot);
        if (!type.equals("2")) throw new IllegalStateException("unsupported encryption type " + type + " for a vault value");
        var parts = s.substring(dot + 1).split("\\|");
        var iv = UNB64.decode(parts[0]);
        var ct = UNB64.decode(parts[1]);
        var mac = UNB64.decode(parts[2]);
        if (!same(mac, hmac(key.mac(), iv, ct))) throw new IllegalStateException("wrong key: the value's MAC does not match");
        return aes(Cipher.DECRYPT_MODE, key.enc(), iv, ct);
    }

    public static String text(String s, SymKey key) {
        var b = decrypt(s, key);
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }

    public static String encrypt(byte[] plain, SymKey key) {
        var iv = random(16);
        var ct = aes(Cipher.ENCRYPT_MODE, key.enc(), iv, plain);
        return "2." + B64.encodeToString(iv) + "|" + B64.encodeToString(ct) + "|" + B64.encodeToString(hmac(key.mac(), iv, ct));
    }

    public static String encrypt(String plain, SymKey key) {
        return plain == null ? null : encrypt(plain.getBytes(StandardCharsets.UTF_8), key);
    }

    public static byte[] decryptRsa(String s, PrivateKey key) {
        var dot = s.indexOf('.');
        var type = s.substring(0, dot);
        if (!type.equals("4")) throw new IllegalStateException("unsupported encryption type " + type + " for an organisation key");
        return rsaOaepSha1(key, UNB64.decode(s.substring(dot + 1).split("\\|")[0]));
    }

    private EncString() {}
}
