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

    private static final boolean DEBUG = Boolean.getBoolean("trustme.debug");

    private static void debug(String message) {
        if (DEBUG) System.err.println("TrustMe: " + message);
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
        if (!enabled()) {
            debug("cache disabled (" + (WINDOWS ? "-Dtrustme.cache=false" : "not Windows") + ")");
            return null;
        }
        Path path = fileFor(keyId);
        if (!Files.isRegularFile(path)) {
            debug("no cached key at " + path);
            return null;
        }
        try {
            byte[] key = Crypt32Util.cryptUnprotectData(Files.readAllBytes(path));
            debug("using cached key from " + path);
            return key;
        } catch (Exception e) {
            // Belongs to another account, corrupt, or DPAPI refused it. Fall back
            // to the password, but say so: a silent miss looks like a broken cache.
            System.err.println("TrustMe: cached key at " + path + " could not be read ("
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + "); asking for the password.");
            return null;
        }
    }

    /** Remembers an unlocked private key. Failure here is never fatal. */
    static void store(String keyId, byte[] privateKey) {
        if (!enabled()) return;
        byte[] sealed = null;
        Path path = fileFor(keyId);
        try {
            Files.createDirectories(directory());
            sealed = Crypt32Util.cryptProtectData(privateKey);
            Files.write(path, sealed);
            debug("remembered key at " + path);
        } catch (IOException | RuntimeException | LinkageError e) {
            // Caching is an optimisation and must not fail the unlock, but a
            // silent failure means every run prompts with no explanation.
            System.err.println("TrustMe: could not remember the key on this machine ("
                    + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + "). You will be asked for the password on every run.");
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
