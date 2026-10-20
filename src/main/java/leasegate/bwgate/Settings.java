package leasegate.bwgate;

import java.nio.file.Files;
import java.nio.file.Path;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import datapotter.datahelper.Data;

/// `~/leasegate/bwgate/settings.toml`: which server and which account, and when the vault locks
/// itself (Bitwarden's vault timeout: after `lockAfterMinutes` without a request, 0 for never, and
/// when Windows locks; `timeoutAction` "lock" or "logout"). No password here; it is typed into the
/// tray and kept nowhere.
@Data
public final class Settings extends Settings_A {
    String server;
    String email;
    int lockAfterMinutes = 15;
    boolean lockOnSystemLock = true;
    String timeoutAction = "lock";

    public boolean logoutOnTimeout() { return "logout".equalsIgnoreCase(timeoutAction); }

    static final TomlMapper TOML = TomlMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();

    public static Settings load(Path file) {
        if (!Files.exists(file)) throw new IllegalStateException("bwgate has no settings yet: write " + file + " with server = '...' and email = '...'");
        try {
            var s = TOML.readValue(file.toFile(), Settings.class);
            if (s.getServer() == null || s.getEmail() == null) throw new IllegalStateException("server and email are both needed");
            return s;
        } catch (IllegalStateException e) { throw new IllegalStateException(file + ": " + e.getMessage(), e); }
        catch (Exception e) { throw new IllegalStateException("cannot read " + file + ": " + e.getMessage(), e); }
    }
}
