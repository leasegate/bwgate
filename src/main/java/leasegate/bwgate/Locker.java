package leasegate.bwgate;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javafx.application.Platform;

/// Bitwarden's vault timeout, for the tray. After `lockAfterMinutes` with no request served, or the
/// moment Windows locks, the vault key and everything decrypted are wiped and every approval is
/// revoked (or, with `timeoutAction = "logout"`, the session goes too). A request that arrives while
/// locked brings up the unlock window and waits for it; several waiting requests share one window.
final class Locker {

    static final Duration POLL = Duration.ofSeconds(3);

    final Settings settings;
    final BwAccount account;
    final BwVault vault;
    final Runnable revokeAll;
    final Supplier<Boolean> askToUnlock;
    volatile Consumer<String> onLocked = why -> {};
    volatile Instant lastUse = Instant.now();
    CompletableFuture<Boolean> unlocking;

    Locker(Settings settings, BwAccount account, BwVault vault, Runnable revokeAll, Supplier<Boolean> askToUnlock) {
        this.settings = settings;
        this.account = account;
        this.vault = vault;
        this.revokeAll = revokeAll;
        this.askToUnlock = askToUnlock;
    }

    Locker start() {
        Thread.ofPlatform().name("bwgate-locker").daemon().start(this::watch);
        return this;
    }

    void touch() { lastUse = Instant.now(); }

    synchronized void lock(String why) {
        if (!account.open() && !settings.logoutOnTimeout()) return;
        revokeAll.run();
        vault.forget();
        if (settings.logoutOnTimeout()) account.logout(); else account.lock();
        Places.log((settings.logoutOnTimeout() ? "logged out: " : "locked: ") + why);
        onLocked.accept(why);
    }

    /// Returns once the vault is open, after asking the human if it was locked; throws if they closed
    /// the window instead.
    void ensureOpen() {
        if (account.open()) return;
        CompletableFuture<Boolean> f;
        synchronized (this) {
            if (unlocking == null || unlocking.isDone()) {
                unlocking = new CompletableFuture<>();
                var mine = unlocking;
                Platform.runLater(() -> mine.complete(askToUnlock.get()));
            }
            f = unlocking;
        }
        var open = f.join() && account.open();
        Places.log(open ? "unlocked for a request" : "a request found it locked; left locked");
        if (!open) throw new IllegalStateException("bwgate is locked: the unlock window was closed");
        touch();
    }

    void watch() {
        while (true) {
            try { Thread.sleep(POLL); } catch (InterruptedException e) { return; }
            if (!account.open()) continue;
            if (settings.isLockOnSystemLock() && SystemLock.locked()) { lock("Windows was locked"); continue; }
            var idle = settings.getLockAfterMinutes();
            if (idle > 0 && Instant.now().isAfter(lastUse.plus(Duration.ofMinutes(idle)))) lock("no request for " + idle + " min");
        }
    }
}
