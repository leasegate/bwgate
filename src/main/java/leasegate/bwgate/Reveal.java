package leasegate.bwgate;

import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import static leasegate.bwgate.J.*;

/// One item decrypted, as JSON: the common fields at the top (username, password, totp, uris,
/// notes, custom fields by name) and the rest of whatever the item type carries (card, identity,
/// ssh key) decrypted in place. Built only for an approved request, and never kept.
public final class Reveal {

    static final Pattern ENC = Pattern.compile("^2\\.[A-Za-z0-9+/=]+\\|[A-Za-z0-9+/=]+\\|[A-Za-z0-9+/=]+$");
    static final String[] SECTIONS = {"card", "identity", "sshKey", "secureNote"};

    public static ObjectNode item(Item i) {
        var out = M.createObjectNode().put("id", i.id()).put("name", i.name()).put("type", i.typeName()).put("folder", i.folder());
        var login = at(i.raw(), "login");
        if (!login.isMissingNode() && !login.isNull()) {
            out.put("username", dec(str(login, "username"), i)).put("password", dec(str(login, "password"), i)).put("totp", dec(str(login, "totp"), i));
            var uris = out.putArray("uris");
            at(login, "uris").forEach(u -> uris.add(dec(str(u, "uri"), i)));
        }
        out.put("notes", dec(str(i.raw(), "notes"), i));
        var fields = out.putObject("fields");
        at(i.raw(), "fields").forEach(f -> fields.put(dec(str(f, "name"), i), dec(str(f, "value"), i)));
        for (var s : SECTIONS) {
            var sec = at(i.raw(), s);
            if (sec.isObject()) out.set(s, decryptAll(sec.deepCopy(), i));
        }
        return out;
    }

    /// One value: `password`, `username`, `totp`, `notes`, `uri` (the first), or a custom field's name.
    public static String field(Item i, String name) { return pick(item(i), name, i.path()); }

    /// The same, from an item already revealed (as the tray sends it to the command line).
    public static String pick(JsonNode all, String name, String what) {
        var v = switch (name.toLowerCase()) {
            case "password", "username", "totp", "notes", "name" -> all.path(name.toLowerCase());
            case "uri" -> all.path("uris").path(0);
            default -> {
                for (var it = all.path("fields").fieldNames(); it.hasNext(); ) {
                    var f = it.next();
                    if (f.equalsIgnoreCase(name)) yield all.path("fields").get(f);
                }
                yield null;
            }
        };
        if (v == null || v.isMissingNode() || v.isNull()) throw new IllegalArgumentException(what + " has no " + name);
        return v.asText();
    }

    static JsonNode decryptAll(ObjectNode n, Item i) {
        n.properties().forEach(e -> {
            var v = e.getValue();
            if (v.isTextual() && ENC.matcher(v.asText()).matches()) n.put(e.getKey(), dec(v.asText(), i));
            else if (v.isObject()) decryptAll((ObjectNode) v, i);
        });
        return n;
    }

    static String dec(String s, Item i) { return s == null ? null : EncString.text(s, i.key()); }

    private Reveal() {}
}
