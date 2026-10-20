package leasegate.bwgate;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.*;

/// Whether the Windows session is locked right now (Win+L, the lock screen after sleep or the
/// screen saver). While it is, the input desktop is Winlogon's, which a user process cannot open
/// or switch to. Polled; false on any other platform or if the check itself fails.
final class SystemLock {

    static final int DESKTOP_SWITCHDESKTOP = 0x0100;
    static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");
    static MethodHandle open, switchTo, close;

    static synchronized void bind() {
        if (open != null) return;
        var linker = Linker.nativeLinker();
        var user32 = SymbolLookup.libraryLookup("user32", Arena.global());
        open = linker.downcallHandle(user32.find("OpenInputDesktop").orElseThrow(), FunctionDescriptor.of(ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT));
        switchTo = linker.downcallHandle(user32.find("SwitchDesktop").orElseThrow(), FunctionDescriptor.of(JAVA_INT, ADDRESS));
        close = linker.downcallHandle(user32.find("CloseDesktop").orElseThrow(), FunctionDescriptor.of(JAVA_INT, ADDRESS));
    }

    static boolean locked() {
        if (!WINDOWS) return false;
        try {
            bind();
            var desk = (MemorySegment) open.invokeExact(0, 0, DESKTOP_SWITCHDESKTOP);
            if (desk.equals(MemorySegment.NULL)) return true;
            try { return (int) switchTo.invokeExact(desk) == 0; }
            finally { var ignored = (int) close.invokeExact(desk); }
        } catch (Throwable t) { return false; }
    }

    private SystemLock() {}
}
