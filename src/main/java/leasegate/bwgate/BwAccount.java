package leasegate.bwgate;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;

import com.fasterxml.jackson.databind.JsonNode;

import static leasegate.bwgate.J.*;

/// One logged-in account, held in memory only: the access and refresh tokens, and the vault key
/// and private key the master password opened. Nothing of it is written to disk. `verify` checks a
/// typed password against the vault key without asking the server, which is what a re-confirm needs.
public final class BwAccount {

    public static final int DEVICE_TYPE_WINDOWS_CLI = 23;

    final BwApi api;
    final String email;
    final String deviceId;
    int iterations;
    String protectedKey;
    String protectedPrivateKey;
    volatile SymKey userKey;
    volatile PrivateKey privateKey;
    String refreshToken;
    Instant accessExpires = Instant.EPOCH;

    public BwAccount(BwApi api, String email, String deviceId) {
        this.api = api;
        this.email = email;
        this.deviceId = deviceId;
    }

    public boolean open() { return userKey != null; }

    /// `provider` and `code` are null on the first try; after a SecondFactor answer, the same
    /// password again with the chosen provider and its code.
    public LoginResult login(String password, Integer provider, String code) {
        var pre = api.prelogin(email);
        if (!pre.ok()) return new LoginResult.Refused("prelogin: HTTP " + pre.status());
        var kdf = at(pre.body(), "kdf").asInt(0);
        if (kdf != 0) return new LoginResult.Refused("this account uses Argon2id; bwgate does PBKDF2 only for now");
        iterations = at(pre.body(), "kdfIterations").asInt(600_000);
        var masterKey = BwCrypto.masterKey(password, email, iterations);
        var form = new LinkedHashMap<String, String>();
        form.put("grant_type", "password");
        form.put("username", email);
        form.put("password", BwCrypto.masterPasswordHash(masterKey, password));
        form.put("scope", "api offline_access");
        form.put("client_id", "cli");
        form.put("deviceType", String.valueOf(DEVICE_TYPE_WINDOWS_CLI));
        form.put("deviceIdentifier", deviceId);
        form.put("deviceName", "bwgate");
        if (provider != null) {
            form.put("twoFactorProvider", provider.toString());
            form.put("twoFactorToken", code);
            form.put("twoFactorRemember", "0");
        }
        var a = api.token(form);
        if (!a.ok()) return refusal(a.body());
        tokens(a.body());
        protectedKey = str(a.body(), "Key");
        protectedPrivateKey = str(a.body(), "PrivateKey");
        java.util.Arrays.fill(masterKey, (byte) 0);
        if (!openKeys(password)) return new LoginResult.Refused("the server accepted the password but it does not open the vault key");
        return new LoginResult.In();
    }

    /// After a lock: the session is still there, so the password alone opens the keys again, with
    /// no server and no second factor (Bitwarden's own Lock). After a log-out, or before the first
    /// login, it is a full login.
    public LoginResult unlock(String password, Integer provider, String code) {
        if (refreshToken == null || protectedKey == null) return login(password, provider, code);
        return openKeys(password) ? new LoginResult.In() : new LoginResult.Refused("wrong master password");
    }

    boolean openKeys(String password) {
        var stretched = BwCrypto.stretch(BwCrypto.masterKey(password, email, iterations));
        try {
            var key = SymKey.of(EncString.decrypt(protectedKey, stretched));
            privateKey = protectedPrivateKey == null ? null : BwCrypto.privateKey(EncString.decrypt(protectedPrivateKey, key));
            userKey = key;
            return true;
        } catch (IllegalStateException wrong) { return false; }
        finally { stretched.wipe(); }
    }

    static LoginResult refusal(JsonNode b) {
        var providers = at(b, "TwoFactorProviders");
        if (providers.isArray() && !providers.isEmpty()) {
            var list = new ArrayList<Integer>();
            providers.forEach(p -> list.add(p.asInt()));
            return new LoginResult.SecondFactor(list);
        }
        var model = at(b, "ErrorModel");
        var msg = str(model, "Message");
        if (msg == null) msg = str(b, "error_description");
        if (msg == null) msg = str(b, "message");
        return new LoginResult.Refused(msg != null ? msg : b.toString());
    }

    /// Whether `password` is this account's master password: it must open the vault key the server
    /// gave at login, and yield the same key.
    /// Also while locked: the encrypted vault key opens only with the right password (its MAC is
    /// checked), so it answers on its own when no key is in memory. bwgate locks itself on idle and on
    /// Win+L, and a re-confirm (blanket mode, a broad request) used to report every password as wrong then.
    public boolean verify(String password) {
        if (protectedKey == null || password == null) return false;
        var open = userKey;
        var stretched = BwCrypto.stretch(BwCrypto.masterKey(password, email, iterations));
        try {
            var key = EncString.decrypt(protectedKey, stretched);
            return open == null || BwCrypto.same(key, open.bytes());
        }
        catch (IllegalStateException wrong) { return false; }
        finally { stretched.wipe(); }
    }

    /// A fresh access token when the current one is within a minute of expiring.
    public synchronized void fresh() {
        if (Instant.now().isBefore(accessExpires.minusSeconds(60))) return;
        var form = new LinkedHashMap<String, String>();
        form.put("grant_type", "refresh_token");
        form.put("client_id", "cli");
        form.put("refresh_token", refreshToken);
        var a = api.token(form);
        if (!a.ok()) {
            logout();
            throw new IllegalStateException("the server ended the session (HTTP " + a.status() + "): the next unlock is a full login");
        }
        tokens(a.body());
    }

    void tokens(JsonNode b) {
        api.accessToken = str(b, "access_token");
        var r = str(b, "refresh_token");
        if (r != null) refreshToken = r;
        accessExpires = Instant.now().plusSeconds(at(b, "expires_in").asLong(3600));
    }

    public boolean refreshTokenHeld() { return refreshToken != null; }

    public SymKey userKey() { return userKey; }

    public PrivateKey privateKey() { return privateKey; }

    /// Bitwarden's Lock: the keys are wiped; the encrypted vault key and the session stay.
    public void lock() {
        var k = userKey;
        userKey = null;
        privateKey = null;
        if (k != null) k.wipe();
    }

    /// Bitwarden's Log out: the session goes too.
    public void logout() {
        lock();
        api.accessToken = null;
        refreshToken = null;
        protectedKey = null;
        protectedPrivateKey = null;
    }

    public void close() { logout(); }
}
