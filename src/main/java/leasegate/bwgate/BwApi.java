package leasegate.bwgate;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;

/// The few HTTP calls a vault client needs, against a Bitwarden or Vaultwarden server: prelogin,
/// the token endpoint, sync, and cipher and folder writes. No secret ever travels here in clear;
/// the server only stores and returns ciphertext.
public final class BwApi {

    public record Answer(int status, JsonNode body) {
        public boolean ok() { return status / 100 == 2; }
    }

    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    final String server;
    volatile String accessToken;

    public BwApi(String server) { this.server = server.replaceAll("/+$", ""); }

    public Answer prelogin(String email) {
        return send(post("/identity/accounts/prelogin", J.M.createObjectNode().put("email", email).toString(), "application/json"));
    }

    public Answer token(Map<String, String> form) {
        return send(post("/identity/connect/token", form(form), "application/x-www-form-urlencoded"));
    }

    public Answer get(String path) { return send(authed(HttpRequest.newBuilder(uri(path)).GET())); }

    public Answer post(String path, JsonNode body) { return send(authed(post(path, body.toString(), "application/json"))); }

    public Answer put(String path, JsonNode body) {
        return send(authed(HttpRequest.newBuilder(uri(path)).PUT(HttpRequest.BodyPublishers.ofString(body == null ? "{}" : body.toString()))
            .header("Content-Type", "application/json")));
    }

    /// Account registration, for the trial's throwaway account only. Vaultwarden still serves the
    /// older endpoint; the identity one is tried first.
    public Answer register(JsonNode body) {
        var a = send(post("/identity/accounts/register", body.toString(), "application/json"));
        return a.status() == 404 ? send(post("/api/accounts/register", body.toString(), "application/json")) : a;
    }

    HttpRequest.Builder post(String path, String body, String type) {
        return HttpRequest.newBuilder(uri(path)).POST(HttpRequest.BodyPublishers.ofString(body)).header("Content-Type", type);
    }

    HttpRequest.Builder authed(HttpRequest.Builder b) {
        if (accessToken == null) throw new IllegalStateException("not logged in");
        return b.header("Authorization", "Bearer " + accessToken);
    }

    URI uri(String path) { return URI.create(server + path); }

    Answer send(HttpRequest.Builder b) {
        try {
            var r = HTTP.send(b.timeout(Duration.ofSeconds(60)).header("Accept", "application/json")
                .header("Bitwarden-Client-Name", "cli").header("Bitwarden-Client-Version", "2025.1.0").build(), HttpResponse.BodyHandlers.ofString());
            var text = r.body();
            return new Answer(r.statusCode(), text == null || text.isBlank() ? J.M.createObjectNode() : J.read(text));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted");
        } catch (Exception e) { throw new IllegalStateException("cannot reach " + server + ": " + e.getMessage(), e); }
    }

    static String form(Map<String, String> m) {
        return new LinkedHashMap<>(m).entrySet().stream().filter(e -> e.getValue() != null)
            .map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));
    }

    static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}
