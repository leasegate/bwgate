package leasegate.bwgate;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/// The key derivation and ciphers a Bitwarden client uses, from the JDK alone. The master key is
/// PBKDF2-SHA256(password, email); the server sees only a hash of it, and the master key, stretched
/// with HKDF into an encryption and a MAC key, opens the vault key the server stores.
public final class BwCrypto {

    static final SecureRandom RANDOM = new SecureRandom();
    static final Base64.Encoder B64 = Base64.getEncoder();
    static final Base64.Decoder UNB64 = Base64.getDecoder();

    public static byte[] masterKey(String password, String email, int iterations) {
        try {
            var spec = new PBEKeySpec(password.toCharArray(), email.trim().toLowerCase().getBytes(StandardCharsets.UTF_8), iterations, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    /// What the server is sent instead of the password: one more PBKDF2 round, keyed by the master
    /// key and salted with the password.
    public static String masterPasswordHash(byte[] masterKey, String password) {
        return B64.encodeToString(pbkdf2Once(masterKey, password.getBytes(StandardCharsets.UTF_8)));
    }

    public static SymKey stretch(byte[] masterKey) {
        return new SymKey(hkdfExpand(masterKey, "enc"), hkdfExpand(masterKey, "mac"));
    }

    static byte[] pbkdf2Once(byte[] password, byte[] salt) {
        var block = Arrays.copyOf(salt, salt.length + 4);
        block[block.length - 1] = 1;
        return hmac(password, block);
    }

    static byte[] hkdfExpand(byte[] prk, String info) {
        var in = Arrays.copyOf(info.getBytes(StandardCharsets.US_ASCII), info.length() + 1);
        in[in.length - 1] = 1;
        return hmac(prk, in);
    }

    public static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (var p : parts) mac.update(p);
            return mac.doFinal();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    public static byte[] aes(int mode, byte[] key, byte[] iv, byte[] data) {
        try {
            var c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) { throw new IllegalStateException("decryption failed", e); }
    }

    public static boolean same(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }

    public static byte[] random(int n) { var b = new byte[n]; RANDOM.nextBytes(b); return b; }

    public static PrivateKey privateKey(byte[] pkcs8) {
        try { return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8)); }
        catch (Exception e) { throw new IllegalStateException("not an RSA private key", e); }
    }

    public static byte[] rsaOaepSha1(PrivateKey key, byte[] data) {
        try {
            var c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            return c.doFinal(data);
        } catch (Exception e) { throw new IllegalStateException("RSA decryption failed", e); }
    }

    /// A fresh account's keys: the public key (SPKI) and private key (PKCS#8), both DER.
    public static byte[][] rsaPair() {
        try {
            var g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            var p = g.generateKeyPair();
            return new byte[][] { p.getPublic().getEncoded(), p.getPrivate().getEncoded() };
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private BwCrypto() {}
}
