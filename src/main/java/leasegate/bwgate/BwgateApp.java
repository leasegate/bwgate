package leasegate.bwgate;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;

import leasegate.core.LeaseEngine;
import leasegate.core.LeaseServer;
import leasegate.core.access.*;
import leasegate.transport.LeaseDeniedException;
import leasegate.transport.Links;
import leasegate.ui.*;
import leasegate.frame.*;

/// The bwgate tray: the master password logs in and opens the vault key, which then stays in this
/// process alone. Every request names an item or a folder and a tier, and is answered from an
/// approval made in the window, or not at all. Quitting forgets the key.
public final class BwgateApp extends Application {

    static final String COLOR = "#175ddc";

    Settings settings;
    BwAccount account;
    BwVault vault;
    PassphraseGate gate;

    public static void main(String[] args) {
        System.setProperty("apple.awt.UIElement", "true");
        launch(args);
    }

    @Override public void init() {
        Platform.setImplicitExit(false);
        settings = Settings.load(Places.settings());
        account = new BwAccount(new BwApi(settings.getServer()), settings.getEmail(), Places.deviceId());
        vault = new BwVault(account);
        gate = PassphraseGate.external(account::verify);
    }

    @Override public void start(Stage stage) {
        if (alreadyRunning()) { System.err.println("bwgate is already running"); Platform.exit(); return; }
        stage.setTitle(Places.PRODUCT);
        var brand = new Brand(Places.PRODUCT, COLOR, new GateIcons(BwgateApp.class, "bwgate"));
        var password = UnlockWindow.show(brand, account, settings, "locked: log in to your vault", "Quit bwgate");
        if (password == null || !gate.unlock(password)) { Platform.exit(); System.exit(0); return; }
        Places.log("started and logged in");
        try { vault.sync(true); }
        catch (RuntimeException e) { GateFrame.tell(brand, "sync failed", e.getMessage()); }

        var rules = new BwRules();
        var engine = new LeaseEngine<BwScope>(rules, new BlanketModeApproval<>(new FxApproval<>(gate, rules, brand), gate),
            new KeyedAppStore<>(Places.home().resolve("keyed-apps.json"), rules));
        engine.trustApproval(new FxTrust<>(gate, rules, brand));
        engine.onExpiring(e -> Platform.runLater(() -> ExpiryWarningWindow.show(engine, gate, brand, e)));
        engine.startSweep();

        var locker = new Locker(settings, account, vault, engine::revokeAllNow, () -> reopen(brand)).start();
        var server = LeaseServer.open(Places.runDir(), Places.PIPE);
        var handler = new Handler(engine, vault, locker);
        Thread.ofPlatform().name("bwgate-control").daemon().start(() -> LeaseServer.serve(server, "bwgate", handler::handle));

        var tray = new TrayShell<>(stage, engine, gate, brand,
            () -> account.open() ? vault.items().size() + " item(s) · " + engine.activeGrants().size() + " approval(s)" : "locked");
        locker.onLocked = why -> tray.notify("locked: " + why);
        tray.addItem(TrayShell.item("Lock now", () -> locker.lock("locked from the tray")))
            .addItem(TrayShell.item("Sync the vault now", () -> Thread.ofPlatform().daemon().start(() -> {
                try { locker.ensureOpen(); vault.sync(true); tray.notify(vault.items().size() + " items"); }
                catch (RuntimeException e) { tray.notify("sync failed: " + e.getMessage()); }
            })))
            .describe("guards the Bitwarden vault", "https://github.com/leasegate/bwgate")
            .quit("Quit bwgate (the vault key is forgotten; requests stop until it starts again)", account::close)
            .install();
    }

    /// The unlock window again, after a lock. True when the vault is open again and synced.
    boolean reopen(Brand brand) {
        var subtitle = account.refreshTokenHeld() ? "locked: type the master password" : "logged out: log in again";
        if (UnlockWindow.show(brand, account, settings, subtitle, "Leave it locked") == null) return false;
        try { vault.sync(true); return true; }
        catch (RuntimeException e) { GateFrame.tell(brand, "sync failed", e.getMessage()); return account.open(); }
    }

    static boolean alreadyRunning() {
        try (var io = Links.open(Places.PRODUCT, Places.runDir(), Places.PIPE)) {
            io.writeFrame("{\"gate\":{\"v\":2,\"op\":\"ping\"}}");
            return io.readFrame() != null;
        } catch (LeaseDeniedException e) { return false; }
    }
}
