package leasegate.bwgate;

/// An organisation's collection, as the last sync saw it: what a shared item must belong to.
/// `readOnly` collections cannot take new items from this account.
public record Collection(String id, String name, String orgId, String orgName, boolean readOnly) {}
