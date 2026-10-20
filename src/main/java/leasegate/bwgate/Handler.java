package leasegate.bwgate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import leasegate.core.ConsumerServer;
import leasegate.core.LeaseEngine;
import leasegate.core.Outcome;
import leasegate.core.Replies;
import leasegate.core.access.Handshake;
import leasegate.core.access.ProcessTree;

import static leasegate.core.Replies.M;

/// One connection on bwgate's pipe, one request. `ping` and `status` name no item and are open to
/// any process of this user; everything else is matched to a scope and goes through the engine,
/// which finds an approval that covers it or asks the human, before the vault is touched.
final class Handler {

    final LeaseEngine<BwScope> engine;
    final BwVault vault;
    final Writer writer;
    final Locker locker;

    Handler(LeaseEngine<BwScope> engine, BwVault vault, Locker locker) {
        this.engine = engine;
        this.vault = vault;
        this.locker = locker;
        this.writer = new Writer(vault);
    }

    void handle(ConsumerServer.Accepted a) {
        var raw = ProcessTree.rawChain(a.peer().pid());
        var io = a.io();
        try (io) {
            var first = io.readFrame();
            var hs = first == null ? null : Handshake.extract(first).orElse(null);
            if (hs == null) { io.writeFrame(Replies.denied("not a bwgate request", "send {\"gate\":{\"op\":..}}")); return; }
            String reply;
            try { reply = answer(a, raw, hs); }
            catch (IllegalArgumentException | IllegalStateException e) { reply = Replies.denied(e.getMessage(), null); }
            io.writeFrame(reply);
        } catch (RuntimeException e) {
            System.err.println("bwgate: request from pid " + a.peer().pid() + " failed: " + e.getMessage());
        }
    }

    String answer(ConsumerServer.Accepted a, List<ProcessTree.RawLink> raw, Handshake hs) {
        var b = hs.body();
        if (!hs.op().equals("ping") && !hs.op().equals("status")) { locker.ensureOpen(); locker.touch(); }
        return switch (hs.op()) {
            case "ping" -> Replies.wrap(M.createObjectNode().put("ok", true).put("product", Places.PRODUCT));
            case "status" -> Replies.wrap(M.createObjectNode().put("ok", true).put("product", Places.PRODUCT).put("locked", !vault.account.open())
                .put("items", vault.items().size()).put("approvals", engine.activeGrants().size()));
            case "list" -> {
                vault.sync(false);
                var folder = b.path("folder").asText(null);
                var s = new BwScope(Tier.LIST, folder, null, folder == null ? "every item's name" : null, hs.minutes());
                yield gated(a, raw, hs, s, () -> {
                    var arr = M.createArrayNode();
                    (folder == null ? vault.items() : vault.inFolder(folder.equals(BwScope.NO_FOLDER) ? null : folder)).forEach(i ->
                        arr.addObject().put("id", i.id()).put("name", i.name()).put("folder", i.folder()).put("type", i.typeName()));
                    return M.createObjectNode().set("items", arr);
                });
            }
            case "get" -> {
                var i = item(b);
                var s = new BwScope(Tier.READ, BwScope.folderOf(i), b.path("folderWide").asBoolean(false) ? null : i.id(),
                    i.path() + (b.hasNonNull("field") ? " -> " + b.get("field").asText() : ""), hs.minutes());
                yield gated(a, raw, hs, s, () -> M.createObjectNode().set("item", Reveal.item(i)));
            }
            case "create" -> {
                vault.sync(false);
                var folder = b.path("folder").asText(null);
                var name = b.path("name").asText();
                var s = new BwScope(Tier.WRITE, folder == null ? BwScope.NO_FOLDER : folder, null, "new item " + name, hs.minutes());
                yield gated(a, raw, hs, s, () -> M.createObjectNode().put("id", writer.create(folder, name, values(b)).id()));
            }
            case "edit" -> {
                var i = item(b);
                var v = values(b);
                var s = new BwScope(Tier.WRITE, BwScope.folderOf(i), i.id(), i.path() + ": change " + String.join(", ", v.keySet()), hs.minutes());
                yield gated(a, raw, hs, s, () -> M.createObjectNode().put("id", writer.edit(i, v).id()));
            }
            case "trash" -> {
                var i = item(b);
                var s = new BwScope(Tier.TRASH, BwScope.folderOf(i), i.id(), i.path(), hs.minutes());
                yield gated(a, raw, hs, s, () -> { writer.trash(i); return M.createObjectNode().put("id", i.id()); });
            }
            default -> Replies.denied("unknown op " + hs.op(), "use status, list, get, create, edit or trash");
        };
    }

    String gated(ConsumerServer.Accepted a, List<ProcessTree.RawLink> raw, Handshake hs, BwScope s, Supplier<ObjectNode> work) {
        var label = (hs.app() != null ? hs.app() : "bwgate") + " " + hs.op() + ": " + (s.detail() == null ? s.folder() : s.detail());
        return switch (engine.attest(a.peer(), raw, s, label)) {
            case Outcome.Refused(var error, var hint) -> Replies.denied(error, hint);
            case Outcome.Allowed(var grant) -> { var out = work.get(); locker.touch(); yield Replies.approved("attested", grant.expiresAt(), out, null); }
        };
    }

    Item item(JsonNode b) {
        vault.sync(false);
        var ref = b.path("item").asText(null);
        if (ref == null) throw new IllegalArgumentException("name the item");
        return vault.find(ref);
    }

    static Map<String, String> values(JsonNode b) {
        var out = new LinkedHashMap<String, String>();
        b.path("values").properties().forEach(e -> out.put(e.getKey(), e.getValue().asText()));
        if (out.isEmpty() && !b.path("allowEmpty").asBoolean(false)) throw new IllegalArgumentException("no values given");
        return out;
    }
}
