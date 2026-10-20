package leasegate.bwgate;

import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import static leasegate.bwgate.J.M;

/// What each `bwgate <verb>` does on the client side. A secret goes where it is asked to go -- a
/// child's environment, the clipboard for a while, or stdout with `--show` -- and nowhere by default,
/// because whatever reaches stdout also reaches every log and transcript that captures it.
final class Commands {

    static final Set<String> PLAIN = Set.of("name", "username", "uri", "id", "folder", "type");
    static final int CLIP_SECONDS = 30;

    static int list(Args a) {
        var body = Client.op("list");
        if (a.word(0) != null) body.put("folder", a.word(0));
        var items = Client.ask(minutes(body, a)).path("items");
        if (a.has("json")) { System.out.println(items.toPrettyString()); return 0; }
        items.forEach(i -> System.out.println(i.path("id").asText() + "  " + path(i) + "  (" + i.path("type").asText() + ")"));
        return 0;
    }

    static int get(Args a) {
        var item = fetch(a, a.word(0), a.word(1));
        var field = a.word(1);
        if (field != null) {
            if (!PLAIN.contains(field.toLowerCase()) && !a.has("show"))
                throw new IllegalArgumentException(field + " is a secret: add --show to print it, or use bwgate clip / bwgate exec");
            System.out.println(pick(item, field));
            return 0;
        }
        System.out.println((a.has("show") ? item : masked(item)).toPrettyString());
        return 0;
    }

    static int clip(Args a) throws Exception {
        var field = a.word(1) == null ? "password" : a.word(1);
        var value = pick(fetch(a, a.word(0), field), field);
        var cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        cb.setContents(new StringSelection(value), null);
        System.err.println("bwgate: " + field + " of " + a.word(0) + " is on the clipboard; it is cleared in " + CLIP_SECONDS + "s");
        Thread.sleep(CLIP_SECONDS * 1000L);
        try { if (value.equals(cb.getData(DataFlavor.stringFlavor))) cb.setContents(new StringSelection(""), null); } catch (Exception ignored) {}
        return 0;
    }

    /// `--env NAME=<item>[:field]` (repeatable; field defaults to password), then `-- command args`.
    static int exec(Args a) throws Exception {
        if (a.after.isEmpty()) throw new IllegalArgumentException("give the command after --");
        var pb = new ProcessBuilder(a.after).inheritIO();
        if (!a.has("env")) throw new IllegalArgumentException("name at least one --env NAME=<item>[:field]");
        for (var spec : a.flags.get("env").split("\n")) {
            var eq = spec.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException("--env wants NAME=<item>[:field], got " + spec);
            var ref = spec.substring(eq + 1);
            var colon = ref.lastIndexOf(':');
            var item = colon > 0 ? ref.substring(0, colon) : ref;
            var field = colon > 0 ? ref.substring(colon + 1) : "password";
            pb.environment().put(spec.substring(0, eq), pick(fetch(a, item, field), field));
        }
        return pb.start().waitFor();
    }

    static int create(Args a) {
        if (a.word(1) == null) throw new IllegalArgumentException("bwgate create <folder|-> <name> [name=value ...]");
        var body = Client.op("create").put("name", a.word(1)).put("allowEmpty", true);
        if (!a.word(0).equals("-")) body.put("folder", a.word(0));
        body.set("values", M.valueToTree(a.values(2)));
        System.out.println(Client.ask(minutes(body, a)).path("id").asText());
        return 0;
    }

    static int edit(Args a) {
        var body = Client.op("edit").put("item", need(a.word(0)));
        body.set("values", M.valueToTree(a.values(1)));
        System.out.println(Client.ask(minutes(body, a)).path("id").asText());
        return 0;
    }

    static int trash(Args a) {
        System.out.println(Client.ask(minutes(Client.op("trash").put("item", need(a.word(0))), a)).path("id").asText() + " moved to the trash");
        return 0;
    }

    static JsonNode fetch(Args a, String item, String field) {
        var body = Client.op("get").put("item", need(item));
        if (field != null) body.put("field", field);
        if (a.has("folder-wide")) body.put("folderWide", true);
        return Client.ask(minutes(body, a)).path("item");
    }

    static String pick(JsonNode shown, String field) { return Reveal.pick(shown, field, path(shown)); }

    static JsonNode masked(JsonNode item) {
        var out = (ObjectNode) item.deepCopy();
        var hidden = new ArrayList<String>();
        out.properties().forEach(e -> { if (!PLAIN.contains(e.getKey()) && !e.getKey().equals("uris") && !e.getValue().isNull()) hidden.add(e.getKey()); });
        hidden.forEach(k -> out.put(k, "(hidden: --show, bwgate clip or bwgate exec)"));
        return out;
    }

    static ObjectNode minutes(ObjectNode body, Args a) {
        if (a.minutes() != null) body.put("minutes", a.minutes());
        return body;
    }

    static String path(JsonNode i) { return i.path("folder").isNull() || i.path("folder").isMissingNode() ? i.path("name").asText() : i.path("folder").asText() + "/" + i.path("name").asText(); }

    static String need(String s) { if (s == null) throw new IllegalArgumentException("name the item: its id, folder/name, or name"); return s; }

    private Commands() {}
}
