package leasegate.bwgate;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.VBox;

import leasegate.ui.ApprovalParts;
import leasegate.frame.*;

/// The tray starts here: the master password logs in to the server and opens the vault key, and
/// nothing else of bwgate starts until it has. When the account wants a second factor, a code field
/// appears and the same password goes again with the code. Returns the password, or null when the
/// human chose to quit; the caller hands it to the gate once and keeps it no longer.
final class UnlockWindow {

    static String show(Brand brand, BwAccount account, Settings settings, String subtitle, String escape) {
        var f = new GateFrame(brand, subtitle).modal().notClosable().inTaskbar();
        var password = new SecretField();
        var code = new TextField();
        code.setPromptText("code from your authenticator app or email");
        code.setVisible(false);
        code.setManaged(false);
        var status = ApprovalParts.small(" ", ApprovalParts.GREY);
        var provider = new Integer[1];
        var result = new String[1];
        Runnable submit = () -> {
            if (password.getText().isEmpty() || password.isDisabled()) return;
            password.setDisable(true);
            code.setDisable(true);
            status.setText("checking…");
            var pw = password.getText();
            var c = code.getText().isBlank() ? null : code.getText().trim();
            Thread.ofPlatform().daemon().start(() -> {
                LoginResult r;
                try { r = account.unlock(pw, c == null ? null : provider[0], c); }
                catch (RuntimeException e) { r = new LoginResult.Refused(e.getMessage()); }
                var done = r;
                Platform.runLater(() -> {
                    password.setDisable(false);
                    code.setDisable(false);
                    switch (done) {
                        case LoginResult.In in -> { result[0] = pw; f.stage.close(); }
                        case LoginResult.SecondFactor sf -> {
                            provider[0] = sf.providers().contains(0) ? 0 : sf.providers().getFirst();
                            code.setVisible(true);
                            code.setManaged(true);
                            code.requestFocus();
                            status.setText("second factor needed (" + (provider[0] == 0 ? "authenticator app" : provider[0] == 1 ? "email" : "provider " + provider[0]) + "): type the code");
                        }
                        case LoginResult.Refused no -> { status.setText(no.message()); password.input().selectAll(); password.requestFocus(); }
                    }
                });
            });
        };
        var keys = new FKeys().bind(KeyCode.ENTER, "Log in", ApprovalParts.GREEN, submit).bind(KeyCode.ESCAPE, escape, "#555", f.stage::close);
        var who = new Label(settings.getEmail() + "  on  " + settings.getServer());
        who.setStyle("-fx-font-weight: bold;");
        var body = new VBox(10, who, new Label("Master password (it opens the vault here and is kept nowhere):"), password, code, status, keys.bar,
            ApprovalParts.small("Enter log in · hold F9 to see the password · Esc " + escape.toLowerCase(), "#777"));
        body.setPadding(new Insets(16));
        body.setPrefWidth(460);
        keys.install(f.scene(body));
        f.stage.setOnShown(e -> { f.stage.toFront(); password.requestFocus(); });
        f.stage.showAndWait();
        return result[0];
    }

    private UnlockWindow() {}
}
