package leasegate.bwgate;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import leasegate.core.access.*;
import leasegate.ui.DurationChips;

import static leasegate.core.access.ScopeLine.*;

/// bwgate's rules. Listing names is the lightest thing; one item's secrets is an ordinary approval;
/// a whole folder, or the whole vault, reaches more and is held to less time; reaching everything,
/// or moving anything to the trash, needs the master password typed again.
final class BwRules implements LeaseRules<BwScope> {

    static final int UNSCOPED_CAP = 60, TRASH_CAP = DurationChips.ATTESTED[0].minutes();

    @Override public String product() { return Places.PRODUCT; }

    @Override public DurationCaps.Result capByScope(DurationCaps.Result base, BwScope s) {
        if (s.tier() == Tier.TRASH && base.minutes() > TRASH_CAP) return new DurationCaps.Result(TRASH_CAP, "moving items to the trash");
        if (s.tier() != Tier.LIST && s.unscoped() && base.minutes() > UNSCOPED_CAP) return new DurationCaps.Result(UNSCOPED_CAP, "the whole vault");
        return base;
    }

    @Override public int keyedMaxMinutes(BwScope s) { return s.item() != null ? 240 : s.folder() != null ? 120 : 60; }

    @Override public int riskBase(BwScope s) {
        if (s.tier() == Tier.LIST) return 0;
        return s.tier() == Tier.TRASH || s.unscoped() ? 2 : 1;
    }

    @Override public boolean needsPassphrase(BwScope s) { return s.tier() == Tier.TRASH || (s.tier() != Tier.LIST && s.unscoped()); }

    @Override public List<ScopeLine> describe(BwScope s) {
        var out = new ArrayList<ScopeLine>();
        out.add(s.tier() == Tier.LIST ? narrow("to " + s.tier().verb + " items (names only, no secrets)")
            : s.tier() == Tier.READ ? caution("to " + s.tier().verb + " items: whoever gets this can use them")
            : wide("to " + s.tier().verb + " items in your vault"));
        out.add(s.folder() == null ? wide("folder: ANY") : narrow("folder: " + s.folder()));
        if (s.tier() != Tier.LIST) out.add(s.item() == null ? caution("item: every item in that folder") : narrow("item: one (" + s.item() + ")"));
        if (s.detail() != null) out.add(note("this request: " + s.detail()));
        return out;
    }

    @Override public ScopeLine summary(BwScope s) {
        var where = (s.folder() == null ? "any folder" : s.folder()) + (s.item() == null ? "" : " · one item");
        return new ScopeLine(s.tier().word + "  ·  " + where, s.unscoped() && s.tier() != Tier.LIST ? Tone.WIDE : Tone.CAUTION);
    }

    @Override public void writeScope(ObjectNode n, BwScope s) {
        n.put("tier", s.tier().word);
        if (s.folder() != null) n.put("folder", s.folder());
        if (s.item() != null) n.put("item", s.item());
    }

    @Override public BwScope readScope(JsonNode n) {
        return new BwScope(Tier.of(n.path("tier").asText("read")), n.hasNonNull("folder") ? n.get("folder").asText() : null,
            n.hasNonNull("item") ? n.get("item").asText() : null, null, null);
    }

    @Override public BwScope stored(BwScope s) { return new BwScope(s.tier(), s.folder(), s.item(), null, null); }
}
