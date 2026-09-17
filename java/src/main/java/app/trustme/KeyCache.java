package app.trustme;

import com.sun.jna.platform.win32.Crypt32Util;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Remembers an unlocked private key for this account, so a key file is unlocked
 * once per machine rather than once per run.
 *
 * <p>On Windows the key is sealed with DPAPI under CurrentUser scope: another
 * account on the same machine cannot read it, and copying the file to another
 * machine yields nothing.
 *
 * <p>On Linux there is no OS-backed secret store guaranteed to be present -
 * no desktop session, no keyring daemon, especially headless or in a
 * container - so the key is instead sealed with AES-256-GCM under a key
 * derived from {@code /etc/machine-id}, and the file is restricted to this
 * user with {@code 0600} permissions. That reproduces "copying the file to
 * another machine yields nothing", but the boundary against another account
 * on the same machine is the filesystem permission, not an OS secret store.
 *
 * <p>Either way, any process running as you can use the cached key, which is
 * the same bargain ssh-agent makes — a decrypted credential at rest in
 * exchange for not retyping a password.
 *
 * <p>On anything else (macOS) the cache is simply disabled and every run asks
 * for the password.
 */
final class KeyCache {

    private KeyCache() {}

    private static final String OS_NAME = System.getProperty("os.name", "").toLowerCase();
    private static final boolean WINDOWS = OS_NAME.startsWith("windows");
    private static final boolean LINUX = OS_NAME.startsWith("linux");

    static boolean enabled() {
        if (!WINDOWS && !LINUX) return false;
        return !"false".equalsIgnoreCase(System.getProperty("trustme.cache", "true"));
    }

    private static final boolean DEBUG = Boolean.getBoolean("trustme.debug");

    private static void debug(String message) {
        if (DEBUG) System.err.println("TrustMe: " + message);
    }

    private static Path directory() {
        if (WINDOWS) {
            String base = System.getenv("LOCALAPPDATA");
            if (base == null || base.isEmpty()) {
                base = System.getProperty("user.home");
            }
            return Paths.get(base, "TrustMe", "keys");
        }
        String base = System.getenv("XDG_CACHE_HOME");
        if (base == null || base.isEmpty()) {
            base = Paths.get(System.getProperty("user.home"), ".cache").toString();
        }
        return Paths.get(base, "trustme", "keys");
    }

    private static Path fileFor(String keyId) {
        return directory().resolve(keyId + ".bin");
    }

    // Binds the Linux cache to this machine, standing in for the OS secret
    // store DPAPI gives Windows. Tries systemd's machine-id, then the older
    // D-Bus one; returns null (caching disabled) if neither is present.
    private static byte[] linuxMachineKey() throws Exception {
        for (String candidate : new String[] {"/etc/machine-id", "/var/lib/dbus/machine-id"}) {
            try {
                String id = Files.readString(Paths.get(candidate), StandardCharsets.UTF_8).strip();
                if (!id.isEmpty()) {
                    return MessageDigest.getInstance("SHA-256")
                            .digest(("trustme-linux-cache:" + id).getBytes(StandardCharsets.UTF_8));
                }
            } catch (IOException ignored) {
                // try the next candidate
            }
        }
        throw new IOException("no /etc/machine-id or /var/lib/dbus/machine-id");
    }

    private static byte[] linuxSeal(byte[] data) throws Exception {
        byte[] key = linuxMachineKey();
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        byte[] sealed = cipher.doFinal(data);
        byte[] out = new byte[nonce.length + sealed.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(sealed, 0, out, nonce.length, sealed.length);
        return out;
    }

    private static byte[] linuxUnseal(byte[] data) throws Exception {
        byte[] key = linuxMachineKey();
        if (data.length < 12) throw new IOException("cached key is truncated");
        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] sealed = Arrays.copyOfRange(data, 12, data.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(sealed);
    }

    /** Returns the remembered private key for this key id, or null. */
    static byte[] load(String keyId) {
        if (!enabled()) {
            debug("cache disabled (" + ((WINDOWS || LINUX) ? "-Dtrustme.cache=false" : "not Windows or Linux") + ")");
            return null;
        }
        Path path = fileFor(keyId);
        if (!Files.isRegularFile(path)) {
            debug("no cached key at " + path);
            return null;
        }
        try {
            byte[] key = WINDOWS
                    ? Crypt32Util.cryptUnprotectData(Files.readAllBytes(path))
                    : linuxUnseal(Files.readAllBytes(path));
            debug("using cached key from " + path);
            return key;
        } catch (Exception e) {
            // Belongs to another account/machine, corrupt, or the seal was
            // refused. Fall back to the password, but say so: a silent miss
            // looks like a broken cache.
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
            Path dir = directory();
            Files.createDirectories(dir);
            if (!WINDOWS) {
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            }
            sealed = WINDOWS ? Crypt32Util.cryptProtectData(privateKey) : linuxSeal(privateKey);
            Files.write(path, sealed);
            if (!WINDOWS) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
            debug("remembered key at " + path);
        } catch (Exception | LinkageError e) {
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
