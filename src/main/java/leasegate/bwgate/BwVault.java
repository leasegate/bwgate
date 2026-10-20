package leasegate.bwgate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static leasegate.bwgate.J.*;

/// The vault as the server last sent it: items with their names and folders decrypted (so they can
/// be listed and matched), everything else still encrypted until one item is asked for. Synced
/// again when older than `MAX_AGE` or after a write.
public final class BwVault {

    static final Duration MAX_AGE = Duration.ofSeconds(30);

    final BwAccount account;
    volatile List<Item> items = List.of();
    volatile Map<String, String> folders = Map.of();
    volatile Map<String, String> orgs = Map.of();
    volatile List<String> skipped = List.of();
    volatile List<Collection> collections = List.of();
    volatile Map<String, SymKey> orgKeysById = Map.of();
    volatile Instant syncedAt = Instant.EPOCH;

    public BwVault(BwAccount account) { this.account = account; }

    public synchronized void sync(boolean force) {
        if (!account.open()) throw new IllegalStateException("bwgate is locked");
        if (!force && Instant.now().isBefore(syncedAt.plus(MAX_AGE))) return;
        account.fresh();
        var a = account.api.get("/api/sync?excludeDomains=true");
        if (!a.ok()) throw new IllegalStateException("sync failed: HTTP " + a.status());
        var user = account.userKey();
        var orgKeys = new HashMap<String, SymKey>();
        var names = new HashMap<String, String>();
        var problems = new ArrayList<String>();
        at(at(a.body(), "profile"), "organizations").forEach(o -> {
            var id = str(o, "id");
            names.put(id, str(o, "name") != null ? str(o, "name") : id);
            var k = str(o, "key");
            if (k == null) { problems.add("organisation " + str(o, "name") + ": the server sent no key"); return; }
            if (account.privateKey() == null) { problems.add("organisation " + str(o, "name") + ": the account has no private key"); return; }
            try { orgKeys.put(id, SymKey.of(EncString.decryptRsa(k, account.privateKey()))); }
            catch (RuntimeException e) { problems.add("organisation " + str(o, "name") + ": its key does not open (" + e.getMessage() + ")"); }
        });
        var fs = new HashMap<String, String>();
        at(a.body(), "folders").forEach(f -> fs.put(str(f, "id"), EncString.text(str(f, "name"), user)));
        var list = new ArrayList<Item>();
        at(a.body(), "ciphers").forEach(c -> {
            if (str(c, "deletedDate") != null) return;
            var org = str(c, "organizationId");
            var base = org != null ? orgKeys.get(org) : user;
            if (base == null) { problems.add("item " + str(c, "id") + ": no key for organisation " + names.getOrDefault(org, org)); return; }
            try {
                var own = str(c, "key");
                var key = own != null ? SymKey.of(EncString.decrypt(own, base)) : base;
                var folderId = str(c, "folderId");
                list.add(new Item(str(c, "id"), EncString.text(str(c, "name"), key), at(c, "type").asInt(), folderId,
                    folderId == null ? null : fs.get(folderId), org, key, c));
            } catch (RuntimeException e) { problems.add("item " + str(c, "id") + ": " + e.getMessage()); }
        });
        var cols = new ArrayList<Collection>();
        at(a.body(), "collections").forEach(c -> {
            var key = orgKeys.get(str(c, "organizationId"));
            if (key == null) return;
            try {
                cols.add(new Collection(str(c, "id"), EncString.text(str(c, "name"), key), str(c, "organizationId"),
                    names.get(str(c, "organizationId")), at(c, "readOnly").asBoolean(false)));
            } catch (RuntimeException e) { problems.add("collection " + str(c, "id") + ": " + e.getMessage()); }
        });
        collections = List.copyOf(cols);
        orgKeysById = Map.copyOf(orgKeys);
        list.sort((x, y) -> x.path().compareToIgnoreCase(y.path()));
        items = List.copyOf(list);
        folders = Map.copyOf(fs);
        orgs = Map.copyOf(names);
        skipped = List.copyOf(problems);
        syncedAt = Instant.now();
    }

    /// Organisation id to name, and what the last sync could not open (never a secret: ids and reasons).
    public Map<String, String> orgs() { return orgs; }

    public List<String> skipped() { return skipped; }

    public List<Collection> collections() { return collections; }

    /// A collection by name, `org/collection` or id; refused when the name is ambiguous or read-only.
    public Collection collection(String ref) {
        var m = collections.stream().filter(c -> c.id().equalsIgnoreCase(ref) || c.name().equalsIgnoreCase(ref)
            || (c.orgName() + "/" + c.name()).equalsIgnoreCase(ref)).toList();
        if (m.isEmpty()) throw new IllegalArgumentException("no collection " + ref + " (bwgate collections lists them)");
        if (m.size() > 1) throw new IllegalArgumentException(m.size() + " collections are named " + ref + "; use organisation/collection or an id");
        if (m.getFirst().readOnly()) throw new IllegalArgumentException("collection " + ref + " is read-only for this account");
        return m.getFirst();
    }

    public SymKey orgKey(String orgId) {
        var k = orgKeysById.get(orgId);
        if (k == null) throw new IllegalStateException("no key for organisation " + orgId);
        return k;
    }

    public String orgName(Item i) { return i.orgId() == null ? null : orgs.getOrDefault(i.orgId(), i.orgId()); }

    /// On lock: every decrypted name and item key goes, along with the keys themselves.
    public synchronized void forget() {
        items = List.of();
        folders = Map.of();
        orgs = Map.of();
        skipped = List.of();
        collections = List.of();
        orgKeysById = Map.of();
        syncedAt = Instant.EPOCH;
    }

    public List<Item> items() { return items; }

    public Map<String, String> folders() { return folders; }

    public Optional<String> folderId(String name) {
        return folders.entrySet().stream().filter(e -> e.getValue().equalsIgnoreCase(name)).map(Map.Entry::getKey).findFirst();
    }

    /// An item by id, by `folder/name`, or by name; a name that matches more than one is refused
    /// with their ids, never guessed.
    public Item find(String ref) {
        var byId = items.stream().filter(i -> i.id().equalsIgnoreCase(ref)).findFirst();
        if (byId.isPresent()) return byId.get();
        var matches = items.stream().filter(i -> i.path().equalsIgnoreCase(ref)).toList();
        if (matches.isEmpty()) matches = items.stream().filter(i -> i.name().equalsIgnoreCase(ref)).toList();
        if (matches.isEmpty()) throw new IllegalArgumentException("no item named " + ref);
        if (matches.size() > 1)
            throw new IllegalArgumentException(matches.size() + " items are named " + ref + "; use an id: "
                + String.join(", ", matches.stream().map(i -> i.id() + " (" + i.path() + ")").toList()));
        return matches.getFirst();
    }

    public List<Item> inFolder(String folder) {
        return items.stream().filter(i -> folder == null ? i.folder() == null : folder.equalsIgnoreCase(i.folder())).toList();
    }
}
