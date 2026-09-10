package app.trustme;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Reader for the .TM container (format version 2).
 *
 * <p>The layout is public by design. The only secret is the password that
 * unlocks the private key held inside it.
 */
final class TmFile {

    private static final byte[] MAGIC = {'T', 'M', 'K', 'F'};
    private static final int VERSION = 2;

    final String appId;
    final String keyId;
    final String apiUrl;
    final byte[] publicKey;
    final byte[] salt;
    final int memoryCostKib;
    final int timeCost;
    final int parallelism;
    final byte[] nonce;
    final byte[] ciphertext;
    final byte[] tag;

    private TmFile(Cursor c) {
        this.appId = c.str8();
        this.keyId = c.str8();
        this.apiUrl = c.str16();
        this.publicKey = c.blob16();
        this.salt = c.take(16);
        this.memoryCostKib = c.u32();
        this.timeCost = c.u32();
        this.parallelism = c.u8();
        this.nonce = c.take(12);
        this.ciphertext = c.blob16();
        this.tag = c.take(16);
    }

    static TmFile load(Path path) {
        byte[] raw;
        try {
            raw = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new TrustMeException("Could not read key file " + path + ": " + e.getMessage());
        }
        if (raw.length < 100) {
            throw new TrustMeException("File is too small to be a key file: " + path);
        }

        byte[] body = Arrays.copyOfRange(raw, 0, raw.length - 32);
        byte[] stated = Arrays.copyOfRange(raw, raw.length - 32, raw.length);
        if (!MessageDigest.isEqual(sha256(body), stated)) {
            throw new TrustMeException("Key file is corrupt: checksum does not match.");
        }

        Cursor c = new Cursor(raw);
        if (!Arrays.equals(c.take(4), MAGIC)) {
            throw new TrustMeException("Not a TrustMe key file: " + path);
        }
        int version = c.u8();
        if (version != VERSION) {
            throw new TrustMeException("Unsupported key file version " + version
                    + ". Regenerate this file from the TrustMe console.");
        }
        c.u8(); // flags
        return new TmFile(c);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new TrustMeException("SHA-256 unavailable: " + e.getMessage());
        }
    }

    private static final class Cursor {
        private final byte[] data;
        private int pos;

        Cursor(byte[] data) {
            this.data = data;
        }

        byte[] take(int count) {
            if (pos + count > data.length) {
                throw new TrustMeException("Key file ended unexpectedly.");
            }
            byte[] out = Arrays.copyOfRange(data, pos, pos + count);
            pos += count;
            return out;
        }

        int u8() {
            return take(1)[0] & 0xff;
        }

        int u16() {
            byte[] b = take(2);
            return ((b[0] & 0xff) << 8) | (b[1] & 0xff);
        }

        int u32() {
            byte[] b = take(4);
            return ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        }

        String str8() {
            return new String(take(u8()), StandardCharsets.UTF_8);
        }

        String str16() {
            return new String(take(u16()), StandardCharsets.UTF_8);
        }

        byte[] blob16() {
            return take(u16());
        }
    }
}
