package leasegate.bwgate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/// Where bwgate keeps its few files (settings, this machine's device id, approvals of keyed apps;
/// never a secret) and the name of its pipe.
public final class Places {

    public static final String
        PRODUCT = "bwgate",
        PIPE = System.getProperty("bwgate.pipe", "leasegate-bwgate");

    public static Path home() {
        var override = System.getProperty("bwgate.home");
        return override != null ? Path.of(override) : Path.of(System.getProperty("user.home"), "leasegate", "bwgate");
    }

    public static Path settings() { return home().resolve("settings.toml"); }

    public static Path runDir() { return home().resolve("run"); }

    /// When the vault was locked and unlocked, and why. Never a secret, never an item.
    public static void log(String line) {
        try {
            Files.createDirectories(home());
            Files.writeString(home().resolve("bwgate.log"), java.time.ZonedDateTime.now().withNano(0) + "  " + line + System.lineSeparator(),
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    /// The server knows this machine by one id, made on first use, so it lists one device.
    public static String deviceId() {
        var f = home().resolve("device-id.txt");
        try {
            if (Files.exists(f)) return Files.readString(f).trim();
            Files.createDirectories(f.getParent());
            var id = UUID.randomUUID().toString();
            Files.writeString(f, id);
            return id;
        } catch (Exception e) { throw new IllegalStateException("cannot keep the device id in " + f, e); }
    }

    private Places() {}
}
