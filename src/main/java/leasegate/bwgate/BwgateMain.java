package leasegate.bwgate;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import leasegate.transport.LeaseDeniedException;

/// `bwgate` with no arguments starts the tray; every other verb asks the running tray. Exit codes:
/// 0 done, 1 refused or failed (the reason on stderr), 2 usage, 3 the tray is not running.
public final class BwgateMain {

    public static void main(String[] args) {
        if (args.length == 0) { BwgateApp.main(args); return; }
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8));
        var verb = args[0];
        if (verb.equals("generate")) { System.out.println(Generate.password(args.length > 1 ? Integer.parseInt(args[1]) : 24)); return; }
        if (!verb.equals("help") && !verb.equals("--help") && !Client.running()) {
            System.err.println("bwgate: the tray is not running (start bwgate.exe and log in)");
            System.exit(3);
        }
        try {
            var a = new Args(args, 1);
            System.exit(switch (verb) {
                case "status" -> { System.out.println(Client.ask(Client.op("status")).toPrettyString()); yield 0; }
                case "list" -> Commands.list(a);
                case "get" -> Commands.get(a);
                case "clip" -> Commands.clip(a);
                case "exec" -> Commands.exec(a);
                case "create" -> Commands.create(a);
                case "edit" -> Commands.edit(a);
                case "trash" -> Commands.trash(a);
                default -> { usage(); yield 2; }
            });
        } catch (LeaseDeniedException e) {
            System.err.println("bwgate: " + e.getMessage() + (e.hint != null ? " (" + e.hint + ")" : ""));
            System.exit(1);
        } catch (IllegalArgumentException e) {
            System.err.println("bwgate: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("bwgate: " + e);
            System.exit(1);
        }
    }

    static void usage() {
        for (var l : new String[] {
            "usage: bwgate                                   start the tray (log in with the master password)",
            "       bwgate status                            item and approval counts",
            "       bwgate list [folder]          [--json]   item names (no secrets)",
            "       bwgate get <item> [field]     [--show]   an item, secrets hidden unless --show",
            "       bwgate clip <item> [field]               a value on the clipboard for 30s (default: password)",
            "       bwgate exec --env NAME=<item>[:field] ... -- <command> [args]",
            "                                                run a command with secrets in its environment only",
            "       bwgate create <folder|-> <name> [name=value ...] [--generate[=N]]",
            "       bwgate edit <item> name=value ... [--generate[=N]]",
            "       bwgate trash <item>                      move to the trash (asks the master password)",
            "       bwgate generate [N]                      a random password, no tray needed",
            "",
            "<item> is an id, folder/name, or a name. Values: username, password, totp, uri, notes, name, or a",
            "custom field's name; name=- reads that value from stdin, so no secret has to sit on a command line.",
            "Every request is approved in the tray's window. --minutes N asks for that long; --folder-wide asks",
            "for the item's whole folder (get, clip, exec)."}) System.err.println(l);
    }

    private BwgateMain() {}
}
