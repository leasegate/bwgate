package leasegate.bwgate;

import java.util.List;

/// How a login ended: in, a second factor wanted (the providers the server offers, by Bitwarden's
/// numbers: 0 authenticator app, 1 email, 3 YubiKey, 7 WebAuthn), or refused with the server's words.
public sealed interface LoginResult {

    record In() implements LoginResult {}

    record SecondFactor(List<Integer> providers) implements LoginResult {}

    record Refused(String message) implements LoginResult {}
}
