package leasegate.bwgate;

/// Prints whether Windows is locked, every 2 seconds, for `seconds` (default 20): run it, press
/// Win+L, unlock, and the lines must say true while it was locked.
/// java --enable-native-access=ALL-UNNAMED -cp <classes> leasegate.bwgate.SystemLockTrial [seconds]
public class SystemLockTrial {
    public static void main(String[] args) throws Exception {
        var seconds = args.length > 0 ? Integer.parseInt(args[0]) : 20;
        for (var i = 0; i < seconds / 2; i++) {
            System.out.println(java.time.LocalTime.now().withNano(0) + " locked=" + SystemLock.locked());
            Thread.sleep(2000);
        }
    }
}
