package leasegate.bwgate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

/// Bitwarden servers answer in PascalCase in some places and camelCase in others (the identity
/// endpoint, older and newer API versions, Vaultwarden), so fields are found ignoring case.
public final class J {

    public static final ObjectMapper M = new ObjectMapper();

    public static JsonNode at(JsonNode n, String name) {
        if (n == null || !n.isObject()) return MissingNode.getInstance();
        if (n.has(name)) return n.get(name);
        for (var it = n.fieldNames(); it.hasNext(); ) {
            var f = it.next();
            if (f.equalsIgnoreCase(name)) return n.get(f);
        }
        return MissingNode.getInstance();
    }

    /// The text of a field, or null when it is absent or JSON null.
    public static String str(JsonNode n, String name) {
        var v = at(n, name);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }

    public static JsonNode read(String json) {
        try { return M.readTree(json); } catch (Exception e) { throw new IllegalStateException("unreadable JSON from the server", e); }
    }

    private J() {}
}
