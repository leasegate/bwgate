# bwgate

**A Bitwarden or Vaultwarden vault that no program can open by itself, and a human who sees every request.**

The official Bitwarden CLI unlocks to a session key (`BW_SESSION`) that opens the whole vault, and that key ends up in an environment variable, a shell history, an agent's transcript. Any program running as you can then read every password you have.

bwgate is a [leasegate](https://github.com/leasegate/leasegate) gate in front of your vault:

- It is its own client, in plain Java (no `bw` executable, no child process). The tray logs in with your master password and holds the decrypted vault key in its own memory. Nothing is written to disk.
- A program asks the tray for one thing: the names in a folder, one item's secrets, a change to one item, or moving one item to the trash. The leasegate approval window shows which process is asking, its whole chain up to the agent or terminal that started it, and exactly what it wants. You choose how far up the chain the approval reaches and for how long.
- Approvals are scoped by tier (`list`, `read`, `write`, `trash`), by folder and by item. Reaching the whole vault, or trashing anything, needs the master password typed again.
- Items are never deleted outright, only moved to the trash, so the trash is your undo.
- The vault locks itself the way Bitwarden's apps do (see Vault timeout below).

## Setup

1. `~/leasegate/bwgate/settings.toml`:

   ```toml
   server = 'https://vault.example.org'
   email  = 'you@example.org'
   ```

2. Start `bwgate.exe` (the tray) and log in with your master password, plus the code if your account has a second factor.

## Use

```
bwgate list [folder]                      item names, no secrets
bwgate get <item> [field] [--show]        an item; secrets stay hidden unless --show
bwgate clip <item> [field]                a value on the clipboard for 30 s (default: password)
bwgate exec --env TOKEN=<item>[:field] -- <command> [args]
bwgate create <folder|-> <name> [name=value ...] [--generate[=N]]
bwgate edit <item> name=value ...
bwgate trash <item>
bwgate generate [N]
```

`<item>` is an id, `folder/name`, or a name. A name that matches more than one item is refused with their ids, never guessed. Values are `username`, `password`, `totp`, `uri`, `notes`, `name`, or a custom field's name. `name=-` reads that value from stdin, so no secret has to sit on a command line.

Secrets go only where you send them: into one command's environment (`exec`), onto the clipboard for a while (`clip`), or to stdout with `--show`. Whatever reaches stdout also reaches every log and transcript that captures it.

## Vault timeout

Bitwarden's apps lock after a period without use and, optionally, when the computer locks; the action is Lock (the default) or Log out. bwgate does the same, set in `settings.toml`:

```toml
lockAfterMinutes = 15        # lock after this long with no request; 0 = never (not advised)
lockOnSystemLock = true      # lock the moment Windows locks
timeoutAction    = "lock"    # or "logout"
```

- **lock**: the vault key, the private key and every decrypted name are wiped from memory and every approval is revoked. The encrypted vault key and the session stay, so unlocking takes the master password alone, with no second factor.
- **logout**: the session goes as well, so the next unlock is a full login.

A request that arrives while bwgate is locked brings up the unlock window and waits for it. The tray menu has **Lock now**. Quitting the tray always forgets everything.

## Building

JDK 25, Maven, [leasegate](https://github.com/leasegate/leasegate) installed first. `mvn package`, or `mvn -Djrexe -Djr.installDir=<folder on PATH> package` for the exe. Windows only for now. Bitwarden's KDF must be PBKDF2 (the default); Argon2id is not supported yet.

`VaultTrial` (under `src/test/java`) runs create, read, edit and trash end to end against a throwaway account named in `~/leasegate/bwgate/trial-account.json`.

Bitwarden is a trademark of Bitwarden Inc. bwgate is an independent project, not affiliated with or endorsed by Bitwarden.

## License

Apache License 2.0.
