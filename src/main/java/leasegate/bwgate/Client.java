package leasegate.bwgate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import leasegate.transport.LeaseDeniedException;
import leasegate.transport.Links;

import static leasegate.bwgate.J.M;

/// The command line's side of the tray: one request per connection. A request blocks while the
/// human looks at the approval window; a refusal comes back as LeaseDeniedException with the
/// gate's own reason and hint.
final class Client {

    static boolean running() {
        try (var io = Links.open(Places.PRODUCT, Places.runDir(), Places.PIPE)) {
            io.writeFrame(frame(op("ping")));
            return io.readFrame() != null;
        } catch (LeaseDeniedException e) { return false; }
    }

    static ObjectNode op(String op) { return M.createObjectNode().put("v", 2).put("op", op).put("app", "bwgate"); }

    static JsonNode ask(ObjectNode body) {
        try (var io = Links.open(Places.PRODUCT, Places.runDir(), Places.PIPE)) {
            io.writeFrame(frame(body));
            var raw = io.readFrame();
            if (raw == null) throw new LeaseDeniedException("bwgate closed the connection", null);
            JsonNode g;
            try { g = M.readTree(raw).path("gate"); } catch (Exception e) { throw new LeaseDeniedException("unreadable reply from bwgate", null); }
            if (!g.path("ok").asBoolean(false)) throw new LeaseDeniedException(g.path("error").asText("denied"), g.path("hint").asText(null));
            return g;
        }
    }

    static String frame(JsonNode body) { return M.createObjectNode().set("gate", body).toString(); }

    private Client() {}
}
