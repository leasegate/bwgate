package leasegate.bwgate;

import leasegate.core.access.Scope;

/// What a request reaches in the vault: one tier, in one folder (or any, when null; items in no
/// folder are `NO_FOLDER`), for one item (by id) or every item there. `detail` -- the item's name,
/// the field asked for -- is shown to the human but not matched.
public record BwScope(Tier tier, String folder, String item, String detail, Integer requestedMinutes) implements Scope<BwScope> {

    public static final String NO_FOLDER = "(no folder)";

    public static String folderOf(Item i) { return i.folder() == null ? NO_FOLDER : i.folder(); }

    @Override public boolean covers(BwScope r) {
        return tier.covers(r.tier) && (folder == null || folder.equalsIgnoreCase(r.folder)) && (item == null || item.equalsIgnoreCase(r.item));
    }

    @Override public BwScope narrowedTo(BwScope r) {
        return new BwScope(r.tier, r.folder != null ? r.folder : folder, r.item != null ? r.item : item, r.detail, r.requestedMinutes);
    }

    @Override public int narrowness() { return (folder != null ? 1 : 0) + (item != null ? 1 : 0); }
}
