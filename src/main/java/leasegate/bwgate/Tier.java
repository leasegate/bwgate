package leasegate.bwgate;

/// What a request does with the vault. Listing shows names only; reading releases secrets;
/// writing creates or changes items; trashing moves one to the trash, and always needs the
/// passphrase. Each is approved on its own: a read approval does not let anything write.
public enum Tier {
    LIST("list", "see the names of"),
    READ("read", "read the secrets of"),
    WRITE("write", "create or change"),
    TRASH("trash", "move to the trash");

    public final String word, verb;

    Tier(String word, String verb) { this.word = word; this.verb = verb; }

    public static Tier of(String s) {
        for (var t : values()) if (t.word.equalsIgnoreCase(s)) return t;
        throw new IllegalArgumentException("unknown tier " + s + " (list, read, write, trash)");
    }

    /// An approval for this tier also answers a request for `asked`: its own tier, and listing.
    public boolean covers(Tier asked) { return asked == this || asked == LIST; }
}
