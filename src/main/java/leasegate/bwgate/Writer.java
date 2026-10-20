package leasegate.bwgate;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;

import static leasegate.bwgate.J.*;

/// Changes to the vault: a new login item, an edit to some of an item's values, an item moved to
/// the trash (never deleted outright: the trash is the human's undo). An edit sends the item back as
/// the server gave it with only the named values re-encrypted, so nothing else it holds is touched.
public final class Writer {

    final BwVault vault;

    public Writer(BwVault vault) { this.vault = vault; }

    /// `values` are the same names `Reveal.field` reads: username, password, totp, uri, notes, or a
    /// custom field's name (created as a hidden field).
    public Item create(String folder, String name, Map<String, String> values) { return create(folder, name, values, null); }

    /// With a collection, the item is the organisation's: encrypted with its key and sent with the
    /// collection it belongs to (an organisation item must belong to one).
    public Item create(String folder, String name, Map<String, String> values, Collection col) {
        var key = col == null ? vault.account.userKey() : vault.orgKey(col.orgId());
        var body = M.createObjectNode().put("type", 1).put("name", EncString.encrypt(name, key)).put("favorite", false).put("reprompt", 0);
        if (col == null) body.putNull("organizationId"); else body.put("organizationId", col.orgId());
        if (folder != null) body.put("folderId", vault.folderId(folder).orElseGet(() -> newFolder(folder)));
        else body.putNull("folderId");
        body.putNull("notes");
        var login = body.putObject("login");
        login.putNull("username").putNull("password").putNull("totp");
        login.putArray("uris");
        body.putArray("fields");
        values.forEach((k, v) -> set(body, k, v, key));
        var a = col == null ? vault.account.api.post("/api/ciphers", body) : vault.account.api.post("/api/ciphers/create",
            M.createObjectNode().<ObjectNode>set("cipher", body).set("collectionIds", M.createArrayNode().add(col.id())));
        if (!a.ok()) throw new IllegalStateException("the server refused the new item: HTTP " + a.status() + " " + a.body());
        vault.sync(true);
        return vault.find(str(a.body(), "id"));
    }

    public Item edit(Item i, Map<String, String> values) {
        var body = (ObjectNode) i.raw().deepCopy();
        body.put("lastKnownRevisionDate", str(i.raw(), "revisionDate"));
        values.forEach((k, v) -> set(body, k, v, i.key()));
        var a = vault.account.api.put("/api/ciphers/" + i.id(), body);
        if (!a.ok()) throw new IllegalStateException("the server refused the edit: HTTP " + a.status() + " " + a.body());
        vault.sync(true);
        return vault.find(i.id());
    }

    public void trash(Item i) {
        var a = vault.account.api.put("/api/ciphers/" + i.id() + "/delete", null);
        if (!a.ok()) throw new IllegalStateException("the server refused to move it to the trash: HTTP " + a.status() + " " + a.body());
        vault.sync(true);
    }

    String newFolder(String name) {
        var a = vault.account.api.post("/api/folders", M.createObjectNode().put("name", EncString.encrypt(name, vault.account.userKey())));
        if (!a.ok()) throw new IllegalStateException("cannot create folder " + name + ": HTTP " + a.status());
        vault.sync(true);
        return str(a.body(), "id");
    }

    static void set(ObjectNode body, String name, String value, SymKey key) {
        var enc = EncString.encrypt(value, key);
        var login = body.get("login") instanceof ObjectNode o ? o : null;
        switch (name.toLowerCase()) {
            case "name" -> body.put("name", enc);
            case "notes" -> body.put("notes", enc);
            case "username", "password", "totp", "uri" -> {
                if (login == null) throw new IllegalArgumentException("only a login item has a " + name);
                if (!name.equalsIgnoreCase("uri")) { login.put(name.toLowerCase(), enc); return; }
                var uris = login.withArray("uris");
                if (uris.isEmpty()) uris.addObject().put("uri", enc).putNull("match");
                else ((ObjectNode) uris.get(0)).put("uri", enc);
            }
            default -> field(body, name, enc, key);
        }
    }

    static void field(ObjectNode body, String name, String enc, SymKey key) {
        var fields = body.withArray("fields");
        for (var f : fields) {
            var n = str(f, "name");
            if (n != null && name.equalsIgnoreCase(EncString.text(n, key))) { ((ObjectNode) f).put("value", enc); return; }
        }
        fields.addObject().put("name", EncString.encrypt(name, key)).put("value", enc).put("type", 1);
    }
}
