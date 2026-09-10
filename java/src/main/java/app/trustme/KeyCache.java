package app.trustme;

import com.sun.jna.platform.win32.Crypt32Util;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Remembers an unlocked private key for this Windows account, so a key file is
 * unlocked once per machine rather than once per run.
 *
 * <p>The key is sealed with DPAPI under CurrentUser scope: another account on the
 * same machine cannot read it, and copying the file to another machine yields
 * nothing. Any process running as you can use it, which is the same bargain
 * ssh-agent makes — a decrypted credential at rest in exchange for not retyping
 * a password.
 *
 * <p>On anything other than Windows the cache is simply disabled and every run
 * asks for the password.
 */
final class KeyCache {

    private KeyCache() {}

    private static final boolean WINDOWS =
            System.getProperty("os.name", "").toLowerCase().startsWith("windows");

    static boolean enabled() {
        if (!WINDOWS) return false;
        return !"false".equalsIgnoreCase(System.getProperty("trustme.cache", "true"));
    }

    private static Path directory() {
        String base = System.getenv("LOCALAPPDATA");
        if (base == null || base.isEmpty()) {
            base = System.getProperty("user.home");
        }
        return Paths.get(base, "TrustMe", "keys");
    }

    private static Path fileFor(String keyId) {
        return directory().resolve(keyId + ".bin");
    }

    /** Returns the remembered private key for this key id, or null. */
    static byte[] load(String keyId) {
        if (!enabled()) return null;
        Path path = fileFor(keyId);
        if (!Files.isRegularFile(path)) return null;
        try {
            return Crypt32Util.cryptUnprotectData(Files.readAllBytes(path));
        } catch (Exception e) {
            // Unreadable because it belongs to another account, is corrupt, or
            // DPAPI refused it. Treat as absent and fall back to the password.
            return null;
        }
    }

    /** Remembers an unlocked private key. Failure here is never fatal. */
    static void store(String keyId, byte[] privateKey) {
        if (!enabled()) return;
        byte[] sealed = null;
        try {
            Files.createDirectories(directory());
            sealed = Crypt32Util.cryptProtectData(privateKey);
            Files.write(fileFor(keyId), sealed);
        } catch (IOException | RuntimeException e) {
            // Caching is an optimisation; carry on without it.
        } finally {
            if (sealed != null) Arrays.fill(sealed, (byte) 0);
        }
    }

    /** Forgets one remembered key. Returns true if something was removed. */
    static boolean forget(String keyId) {
        try {
            return Files.deleteIfExists(fileFor(keyId));
        } catch (IOException e) {
            return false;
        }
    }
}
