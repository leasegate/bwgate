package leasegate.bwgate;

import com.fasterxml.jackson.databind.JsonNode;

/// One vault item as the gate addresses it: its id, decrypted name and folder, and the key its
/// values are encrypted with (the item's own key, else its organisation's, else the user's).
/// `raw` is the cipher exactly as the server sent it, still encrypted.
public record Item(String id, String name, int type, String folderId, String folder, String orgId, SymKey key, JsonNode raw) {

    public String typeName() {
        return switch (type) {
            case 1 -> "login";
            case 2 -> "note";
            case 3 -> "card";
            case 4 -> "identity";
            case 5 -> "ssh key";
            default -> "type " + type;
        };
    }

    /// `folder/name`, or the name alone when the item is in no folder.
    public String path() { return folder == null ? name : folder + "/" + name; }
}
