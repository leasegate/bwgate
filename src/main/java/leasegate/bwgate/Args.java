package leasegate.bwgate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/// The command line, split into words and `--flags`. `name=value` words become an item's values; a
/// value of `-` is read as one line from stdin, so a secret never has to sit on a command line.
final class Args {

    final List<String> words = new ArrayList<>();
    final Map<String, String> flags = new LinkedHashMap<>();
    final List<String> after = new ArrayList<>();

    Args(String[] argv, int from) {
        var i = from;
        for (; i < argv.length; i++) {
            var a = argv[i];
            if (a.equals("--")) { i++; break; }
            if (a.startsWith("--")) {
                var eq = a.indexOf('=');
                if (eq > 0) flags.merge(a.substring(2, eq), a.substring(eq + 1), (x, y) -> x + "\n" + y);
                else if (takesValue(a.substring(2)) && i + 1 < argv.length) flags.merge(a.substring(2), argv[++i], (x, y) -> x + "\n" + y);
                else flags.put(a.substring(2), "");
            } else words.add(a);
        }
        for (; i < argv.length; i++) after.add(argv[i]);
    }

    static boolean takesValue(String flag) { return flag.equals("env") || flag.equals("minutes"); }

    boolean has(String flag) { return flags.containsKey(flag); }

    String word(int i) { return i < words.size() ? words.get(i) : null; }

    Integer minutes() { return has("minutes") ? Integer.valueOf(flags.get("minutes")) : null; }

    /// `name=value` words from index `from` on, plus `--generate[=N]` as the password.
    Map<String, String> values(int from) {
        var out = new LinkedHashMap<String, String>();
        for (var w : words.subList(Math.min(from, words.size()), words.size())) {
            var eq = w.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException("expected name=value, got " + w);
            var v = w.substring(eq + 1);
            out.put(w.substring(0, eq), v.equals("-") ? stdinLine(w.substring(0, eq)) : v);
        }
        if (has("generate")) out.put("password", Generate.password(flags.get("generate").isEmpty() ? 24 : Integer.parseInt(flags.get("generate"))));
        return out;
    }

    static BufferedReader stdin;

    static String stdinLine(String name) {
        try {
            if (stdin == null) stdin = new BufferedReader(new InputStreamReader(System.in));
            var line = stdin.readLine();
            if (line == null) throw new IllegalArgumentException("stdin ended before the value of " + name);
            return line;
        } catch (java.io.IOException e) { throw new IllegalArgumentException("cannot read stdin", e); }
    }
}
