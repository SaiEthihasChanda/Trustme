package app.trustme;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Reads secrets from TrustMe.
 *
 * <pre>{@code
 * String key = TrustMe.get("STRIPE_API_KEY");
 * }</pre>
 *
 * <p>The private key never leaves this process and is never sent anywhere. Each
 * request is authenticated with a freshly signed, single-use assertion that
 * expires in sixty seconds.
 *
 * <p>The key file is found from {@code -Dtrustme.keyfile}, or by looking for a
 * single .TM file in the working directory, or by asking on a terminal.
 *
 * <p>The password is taken, in order, from {@code -Dtrustme.password},
 * {@code -Dtrustme.password-file}, a terminal prompt, or standard input. In a
 * pipeline prefer stdin or a password file: a value passed inline on the command
 * line is visible to anyone who can list processes on the machine.
 */
public final class TrustMe {

    private static final Map<String, TrustMe> CACHE = new ConcurrentHashMap<>();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final TmFile file;
    private final PrivateKey privateKey;

    private TrustMe(TmFile file, PrivateKey privateKey) {
        this.file = file;
        this.privateKey = privateKey;
    }

    /** Fetches a secret using the default key file and password. */
    public static String get(String secretName) {
        return defaultInstance().fetch(secretName);
    }

    /**
     * Points {@link #get(String)} at a specific key file, instead of relying on
     * {@code -Dtrustme.keyfile} or on finding one in the working directory. The
     * password is still asked for, or read from stdin, on first use.
     */
    public static synchronized void useKeyFile(Path keyFile) {
        if (!Files.isRegularFile(keyFile)) {
            throw new TrustMeException("No such key file: " + keyFile);
        }
        defaultKeyFile = keyFile;
    }

    /** As {@link #useKeyFile(Path)}, taking a plain path string. */
    public static void useKeyFile(String keyFilePath) {
        useKeyFile(Paths.get(keyFilePath));
    }

    /**
     * Opens a specific key file. If this machine already remembers the key from
     * an earlier unlock, no password is needed; otherwise one is asked for, read
     * from stdin, or taken from the command line as usual.
     */
    public static TrustMe using(Path keyFile) {
        String slot = keyFile.toAbsolutePath().toString();
        TrustMe existing = CACHE.get(slot);
        if (existing != null) return existing;
        // The header is plaintext, so the key id is readable without unlocking
        // anything. That is what makes a cache lookup possible before prompting.
        TmFile file = TmFile.load(keyFile);
        byte[] remembered = KeyCache.load(file.keyId);
        TrustMe result = remembered != null
                ? fromPrivateKey(file, remembered, keyFile)
                : unlock(file, keyFile, resolvePassword());
        CACHE.put(slot, result);
        return result;
    }
    /** Forgets a key this machine has remembered, so the next run asks again. */
    public static boolean forget(Path keyFile) {
        TmFile file = TmFile.load(keyFile);
        CACHE.remove(keyFile.toAbsolutePath().toString());
        return KeyCache.forget(file.keyId);
    }
    /** As {@link #forget(Path)}, taking a plain path string. */
    public static boolean forget(String keyFilePath) {
        return forget(Paths.get(keyFilePath));
    }
    /** As {@link #using(Path)}, taking a plain path string. */
    public static TrustMe using(String keyFilePath) {
        return using(Paths.get(keyFilePath));
    }

    /** As {@link #using(Path, String)}, taking a plain path string. */
    public static TrustMe using(String keyFilePath, String password) {
        return using(Paths.get(keyFilePath), password);
    }

    /** Opens a specific key file with an explicit password. */
    public static TrustMe using(Path keyFile, String password) {
        // The password is part of the cache key so that presenting a different
        // one re-runs the unlock and fails, rather than quietly handing back an
        // instance that an earlier correct password opened.
        String cacheKey = keyFile.toAbsolutePath() + "#" + sha256Hex(password);
        return CACHE.computeIfAbsent(cacheKey, ignored -> unlock(TmFile.load(keyFile), keyFile, password));
    }

    private static String sha256Hex(String input) {
        try {
            return hex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new TrustMeException("SHA-256 unavailable: " + e.getMessage(), e);
        }
    }

    /** Fetches a secret through this already-unlocked key file. */
    public String fetch(String secretName) {
        if (secretName == null || !secretName.matches("[A-Za-z_][A-Za-z0-9_]{0,63}")) {
            throw new TrustMeException("Invalid secret name: " + secretName);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(file.apiUrl) + "/secret"))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + assertion())
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"secretName\":\"" + secretName + "\"}", StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new TrustMeException("Could not reach TrustMe: " + e.getMessage(), e);
        }

        if (response.statusCode() != 200) {
            String reason = Json.string(response.body(), "error");
            throw new TrustMeException(describe(
                    reason != null ? reason : "HTTP " + response.statusCode(), secretName));
        }

        String value = Json.string(response.body(), "value");
        if (value == null) throw new TrustMeException("Malformed response from TrustMe.");
        return value;
    }

    /**
     * Turns a server error code into something a person can act on. The secret
     * name is always included: a bare "not found" is useless when a config file
     * references a dozen of them.
     */
    private String describe(String code, String secretName) {
        String app = file.appId;
        String quoted = "\"" + secretName + "\"";
        String appQuoted = "\"" + app + "\"";
        switch (code) {
            case "secret_not_found":
                return "Secret " + quoted + " does not exist in application " + appQuoted
                        + ". Add it in the TrustMe console.";
            case "key_revoked":
                return "The key file for application " + appQuoted + " has been revoked (while fetching "
                        + quoted + "). Generate a new one in the TrustMe console.";
            case "unknown_key":
                return "The key file for application " + appQuoted + " is not registered with TrustMe"
                        + " (while fetching " + quoted + "). Generate a new one in the TrustMe console.";
            case "bad_signature":
                return "TrustMe rejected the request for " + quoted + ": the signature did not verify."
                        + " The key file may not match what the console holds for " + appQuoted + ".";
            case "replay_detected":
            case "bad_lifetime":
                return "TrustMe rejected the request for " + quoted + " (" + code
                        + "). Check that this machine's clock is correct.";
            case "decrypt_failed":
                return "TrustMe could not decrypt " + quoted + " on the server. This is a server-side"
                        + " problem, not something in your application.";
            default:
                return "TrustMe refused the request for " + quoted + " in application " + appQuoted
                        + ": " + code;
        }
    }

    /** The application id this key file belongs to. */
    public String appId() {
        return file.appId;
    }

    // Resolved once per process. Standard input in particular can only be read
    // once, so a second get() must not go looking for the password again.
    private static Path defaultKeyFile;


    private static synchronized TrustMe defaultInstance() {
        if (defaultKeyFile == null) defaultKeyFile = resolveKeyFile();

        return using(defaultKeyFile);
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static final String PROP_KEY_FILE = "trustme.keyfile";
    private static final String PROP_PASSWORD = "trustme.password";
    private static final String PROP_PASSWORD_FILE = "trustme.password-file";

    private static List<Path> keyFilesHere() {
        try (Stream<Path> entries = Files.list(Paths.get(""))) {
            return entries
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".tm"))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            return List.of();
        }
    }

    static Path resolveKeyFile() {
        String configured = System.getProperty(PROP_KEY_FILE);
        if (configured != null && !configured.isBlank()) {
            Path path = Paths.get(configured.trim());
            if (!Files.isRegularFile(path)) {
                throw new TrustMeException("-D" + PROP_KEY_FILE + " points at a missing file: " + configured);
            }
            return path;
        }

        List<Path> found = keyFilesHere();
        if (found.size() == 1) return found.get(0);

        Console console = System.console();
        if (console != null) {
            String typed = console.readLine(found.isEmpty()
                    ? "Path to your .TM key file: "
                    : "Several .TM files are here. Path to the one to use: ");
            if (typed != null && !typed.isBlank()) {
                Path path = Paths.get(typed.trim());
                if (!Files.isRegularFile(path)) {
                    throw new TrustMeException("No such file: " + typed.trim());
                }
                return path;
            }
        }

        throw new TrustMeException(found.isEmpty()
                ? "No .TM key file found. Pass -D" + PROP_KEY_FILE + "=<path>, or run where one is present."
                : "Several .TM files found. Pass -D" + PROP_KEY_FILE + "=<path> to choose one.");
    }

    static String resolvePassword() {
        String inline = System.getProperty(PROP_PASSWORD);
        if (inline != null && !inline.isEmpty()) return inline;

        String file = System.getProperty(PROP_PASSWORD_FILE);
        if (file != null && !file.isBlank()) {
            try {
                return Files.readString(Paths.get(file.trim()), StandardCharsets.UTF_8).strip();
            } catch (IOException e) {
                throw new TrustMeException("Could not read -D" + PROP_PASSWORD_FILE + ": " + e.getMessage());
            }
        }

        Console console = System.console();
        if (console != null) {
            char[] typed = console.readPassword("TrustMe key file password: ");
            if (typed != null && typed.length > 0) return new String(typed);
            throw new TrustMeException("No password entered.");
        }

        // No java.io.Console: either a pipeline, or an IDE that redirected
        // the streams. Stdin is the only route left, and the prompt has to be
        // printed explicitly - without it an IDE run just hangs with no hint
        // that anything is waiting for input.
        try {
            System.err.print("TrustMe key file password: ");
            System.err.flush();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line = reader.readLine();
            System.err.println();
            if (line != null && !line.isEmpty()) return line;
        } catch (IOException ignored) {
            // fall through to the error below
        }

        throw new TrustMeException("No password available. Pipe it on stdin, or pass -D"
                + PROP_PASSWORD_FILE + "=<path>, or -D" + PROP_PASSWORD + "=<value>.");
    }

    private static TrustMe fromPrivateKey(TmFile file, byte[] pkcs8, Path keyFile) {
        try {
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            return new TrustMe(file, key);
        } catch (Exception e) {
            throw new TrustMeException("Key file " + keyFile.getFileName()
                    + " does not contain a usable P-256 key.", e);
        } finally {
            java.util.Arrays.fill(pkcs8, (byte) 0);
        }
    }
    private static TrustMe unlock(TmFile file, Path keyFile, String password) {
        Argon2BytesGenerator argon = new Argon2BytesGenerator();
        argon.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(file.salt)
                .withMemoryAsKB(file.memoryCostKib)
                .withIterations(file.timeCost)
                .withParallelism(file.parallelism)
                .build());
        byte[] derived = new byte[32];
        argon.generateBytes(password.toCharArray(), derived);
        byte[] pkcs8;
        try {
            // The GCM tag doubles as the password check: a wrong password fails
            // here rather than producing plausible-looking rubbish.
            byte[] sealed = new byte[file.ciphertext.length + file.tag.length];
            System.arraycopy(file.ciphertext, 0, sealed, 0, file.ciphertext.length);
            System.arraycopy(file.tag, 0, sealed, file.ciphertext.length, file.tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(derived, "AES"),
                    new GCMParameterSpec(128, file.nonce));
            pkcs8 = cipher.doFinal(sealed);
        } catch (Exception e) {
            throw new TrustMeException("Incorrect password for " + keyFile.getFileName() + ".");
        } finally {
            java.util.Arrays.fill(derived, (byte) 0);
        }
        // Remember it for next time before the working copy is wiped.
        KeyCache.store(file.keyId, pkcs8);
        return fromPrivateKey(file, pkcs8, keyFile);
    }

    private String assertion() {
        long now = System.currentTimeMillis() / 1000L;
        byte[] jti = new byte[16];
        new SecureRandom().nextBytes(jti);

        String header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"" + file.keyId + "\"}";
        String payload = "{\"iss\":\"" + file.appId + "\",\"aud\":\"trustme\",\"iat\":" + now
                + ",\"exp\":" + (now + 60) + ",\"jti\":\"" + hex(jti) + "\"}";
        String signingInput = base64Url(header.getBytes(StandardCharsets.UTF_8))
                + "." + base64Url(payload.getBytes(StandardCharsets.UTF_8));

        try {
            // P1363 gives the raw r||s layout JOSE expects; the default
            // SHA256withECDSA would emit a DER sequence the server rejects.
            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signingInput + "." + base64Url(signer.sign());
        } catch (Exception e) {
            throw new TrustMeException("Could not sign the assertion: " + e.getMessage(), e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
