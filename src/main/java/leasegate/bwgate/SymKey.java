package leasegate.bwgate;

import java.util.Arrays;

/// A Bitwarden symmetric key: 32 bytes for AES-256-CBC and 32 for HMAC-SHA256. The user's vault
/// key, an organisation's key and an item's own key all have this shape.
public record SymKey(byte[] enc, byte[] mac) {

    public SymKey {
        if (enc.length != 32 || mac.length != 32) throw new IllegalArgumentException("a vault key is 32 + 32 bytes");
    }

    public static SymKey of(byte[] both) {
        if (both.length != 64) throw new IllegalArgumentException("a vault key is 64 bytes, got " + both.length);
        return new SymKey(Arrays.copyOfRange(both, 0, 32), Arrays.copyOfRange(both, 32, 64));
    }

    public byte[] bytes() {
        var out = Arrays.copyOf(enc, 64);
        System.arraycopy(mac, 0, out, 32, 32);
        return out;
    }

    public void wipe() { Arrays.fill(enc, (byte) 0); Arrays.fill(mac, (byte) 0); }
}
