package leasegate.bwgate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.UUID;

import static leasegate.bwgate.J.*;

/// The vault client end to end against a real server, on a throwaway account the trial registers
/// itself (its password is kept in `<home>/trial-account.json`, never in the repository): log in,
/// check the password locally, create an item in a folder, read it back decrypted, edit one value,
/// move it to the trash. The server is the one in bwgate's settings, or the first argument.
/// java -cp <classes> leasegate.bwgate.VaultTrial [server]
public class VaultTrial {

    static int failed;

    public static void main(String[] args) throws Exception {
        var key = SymKey.of(BwCrypto.random(64));
        var enc = EncString.encrypt("secret ünïcode", key);
        check("a value round-trips", EncString.text(enc, key).equals("secret ünïcode"));
        var other = SymKey.of(BwCrypto.random(64));
        check("another key is refused by the MAC, not decrypted into rubbish", refuses(() -> EncString.text(enc, other)));

        var server = args.length > 0 ? args[0] : Settings.load(Places.settings()).getServer();
        var file = Places.home().resolve("trial-account.json");
        var api = new BwApi(server);
        if (!Files.exists(file)) register(api, file);
        var acc = read(Files.readString(file));
        var email = str(acc, "email");
        var password = str(acc, "password");

        var account = new BwAccount(api, email, str(acc, "device"));
        var wrong = account.login(password + "x", null, null);
        check("a wrong password is refused by the server", wrong instanceof LoginResult.Refused);
        System.out.println("    server said: " + ((LoginResult.Refused) wrong).message());
        check("the right password logs in", account.login(password, null, null) instanceof LoginResult.In);
        check("the vault key opened", account.open());
        check("verify: the right password, locally", account.verify(password));
        check("verify: a wrong one, locally", !account.verify(password + "x"));

        var vault = new BwVault(account);
        vault.sync(true);
        var writer = new Writer(vault);
        var values = new LinkedHashMap<String, String>();
        values.put("username", "trial-user");
        values.put("password", "first-Pässword!");
        values.put("uri", "https://example.org/login");
        values.put("api key", "k-123");
        var name = "trial item " + UUID.randomUUID().toString().substring(0, 8);
        var item = writer.create("bwgate-trial", name, values);
        check("created in its folder", "bwgate-trial".equals(item.folder()) && name.equals(item.name()));
        check("found again by folder/name", vault.find("bwgate-trial/" + name).id().equals(item.id()));
        var shown = Reveal.item(item);
        System.out.println("    " + shown);
        check("username and password decrypt", "trial-user".equals(shown.path("username").asText()) && Reveal.field(item, "password").equals("first-Pässword!"));
        check("uri and custom field decrypt", Reveal.field(item, "uri").equals("https://example.org/login") && Reveal.field(item, "API KEY").equals("k-123"));

        var edited = writer.edit(item, java.util.Map.of("password", "second-Pässword?"));
        check("an edit changes the password", Reveal.field(edited, "password").equals("second-Pässword?"));
        check("...and leaves the rest alone", Reveal.field(edited, "username").equals("trial-user") && Reveal.field(edited, "api key").equals("k-123"));

        writer.trash(edited);
        check("trashed items are gone from the list", vault.items().stream().noneMatch(i -> i.id().equals(item.id())));

        account.close();
        System.out.println(failed == 0 ? "ALL CHECKS PASSED" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void register(BwApi api, Path file) throws Exception {
        var email = "bwgate-trial-" + UUID.randomUUID().toString().substring(0, 8) + "@example.org";
        var password = "Trial-" + UUID.randomUUID();
        var iterations = 600_000;
        var master = BwCrypto.masterKey(password, email, iterations);
        var user = SymKey.of(BwCrypto.random(64));
        var pair = BwCrypto.rsaPair();
        var body = M.createObjectNode().put("email", email).put("name", "bwgate trial").put("kdf", 0).put("kdfIterations", iterations)
            .put("masterPasswordHash", BwCrypto.masterPasswordHash(master, password))
            .put("key", EncString.encrypt(user.bytes(), BwCrypto.stretch(master)));
        body.putNull("masterPasswordHint");
        body.putObject("keys").put("publicKey", BwCrypto.B64.encodeToString(pair[0])).put("encryptedPrivateKey", EncString.encrypt(pair[1], user));
        var a = api.register(body);
        System.out.println("    register: HTTP " + a.status() + " " + a.body());
        if (!a.ok()) throw new IllegalStateException("could not register the trial account");
        Files.createDirectories(file.getParent());
        Files.writeString(file, M.createObjectNode().put("email", email).put("password", password).put("device", UUID.randomUUID().toString()).toString());
    }

    static boolean refuses(Runnable r) {
        try { r.run(); return false; } catch (IllegalStateException e) { return true; }
    }

    static void check(String label, boolean ok) {
        if (!ok) failed++;
        System.out.println((ok ? "ok - " : "FAILED - ") + label);
    }
}
