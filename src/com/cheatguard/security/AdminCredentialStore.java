package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * On-disk store for the administrator password.
 *
 * <p>Design goals, in order:
 *
 * <ol>
 *   <li><b>The password cannot be recovered from anything that ships.</b> Only a
 *       PBKDF2-HMAC-SHA256 digest with a random 16-byte salt and a high iteration
 *       count is written. There is no default password anywhere in the source, the
 *       jar or the installer, so decompiling the application or reading the
 *       repository reveals nothing usable.</li>
 *   <li><b>The record cannot be moved between computers.</b> Every record carries
 *       an HMAC keyed by this machine's identity, so a credential file taken from
 *       a machine whose password is known is rejected here.</li>
 *   <li><b>Failed attempts cannot be wiped by editing the file.</b> The attempt
 *       counter and lockout deadline are inside the authenticated payload.</li>
 * </ol>
 *
 * <p>Known boundary: an attacker with local administrator rights can delete the
 * file and run first-time setup again. That gives them a <em>new</em> password, not
 * the old one, and every session log already sealed with the previous password
 * stays unreadable. Preventing even that requires a server-side account, which is
 * what the planned university portal will provide.
 */
public final class AdminCredentialStore {

    private static final String FORMAT = "cg1";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    /** Attempts allowed before a cooling-off period begins. */
    public static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_BASE_MS = 30_000L;
    private static final long LOCKOUT_MAX_MS = 15 * 60_000L;

    private final File file;

    public AdminCredentialStore() {
        this(new File(AppPaths.getConfigDirectory(), "admin.cred"));
    }

    AdminCredentialStore(File file) {
        this.file = file;
    }

    /** Immutable snapshot of the stored record. */
    record Record(int iterations, byte[] salt, byte[] hash, int failures, long lockedUntil) {
    }

    public boolean isConfigured() {
        return read() != null;
    }

    /** True when the file exists but its contents are not trustworthy. */
    public boolean isTampered() {
        return file.isFile() && read() == null;
    }

    public File getFile() {
        return file;
    }

    /** Store a brand-new password, replacing any existing record. */
    public void save(char[] password) throws IOException {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);
        write(new Record(ITERATIONS, salt, hash, 0, 0L));
    }

    /**
     * Check a password and update the attempt counter.
     *
     * @return the outcome, including remaining lockout time when applicable
     */
    public Result verify(char[] password) {
        Record record = read();
        if (record == null) return Result.notConfigured();

        long now = System.currentTimeMillis();
        if (record.lockedUntil() > now) {
            return Result.lockedOut(record.lockedUntil() - now);
        }

        byte[] candidate = derive(password, record.salt(), record.iterations());
        if (MessageDigest.isEqual(record.hash(), candidate)) {
            writeQuietly(new Record(record.iterations(), record.salt(), record.hash(), 0, 0L));
            return Result.ok();
        }

        int failures = record.failures() + 1;
        long lockedUntil = 0L;
        if (failures >= MAX_ATTEMPTS) {
            // Back off further on each additional group of failures, capped.
            long factor = 1L << Math.min(failures - MAX_ATTEMPTS, 5);
            lockedUntil = now + Math.min(LOCKOUT_BASE_MS * factor, LOCKOUT_MAX_MS);
        }
        writeQuietly(new Record(record.iterations(), record.salt(), record.hash(), failures, lockedUntil));
        int left = Math.max(0, MAX_ATTEMPTS - failures);
        return lockedUntil > now
                ? Result.lockedOut(lockedUntil - now)
                : Result.wrong(left);
    }

    /** Outcome of a verification attempt. */
    public record Result(boolean success, boolean configured, long lockedForMs, int attemptsLeft) {
        static Result ok() { return new Result(true, true, 0L, MAX_ATTEMPTS); }
        static Result wrong(int left) { return new Result(false, true, 0L, left); }
        static Result lockedOut(long ms) { return new Result(false, true, ms, 0); }
        static Result notConfigured() { return new Result(false, false, 0L, MAX_ATTEMPTS); }
    }

    // ------------------------------------------------------- file read / write

    private Record read() {
        try {
            if (!file.isFile()) return null;
            String line = Files.readString(file.toPath(), StandardCharsets.UTF_8).trim();
            String[] p = line.split("\\|");
            if (p.length != 7 || !FORMAT.equals(p[0])) return null;

            String payload = String.join("|", p[0], p[1], p[2], p[3], p[4], p[5]);
            byte[] expected = Base64.getDecoder().decode(p[6]);
            if (!MessageDigest.isEqual(expected, mac(payload))) return null; // moved or edited

            return new Record(
                    Integer.parseInt(p[1]),
                    Base64.getDecoder().decode(p[2]),
                    Base64.getDecoder().decode(p[3]),
                    Integer.parseInt(p[4]),
                    Long.parseLong(p[5]));
        } catch (Exception e) {
            return null;
        }
    }

    private void write(Record r) throws IOException {
        Base64.Encoder enc = Base64.getEncoder();
        String payload = String.join("|",
                FORMAT,
                Integer.toString(r.iterations()),
                enc.encodeToString(r.salt()),
                enc.encodeToString(r.hash()),
                Integer.toString(r.failures()),
                Long.toString(r.lockedUntil()));
        String line = payload + "|" + enc.encodeToString(mac(payload));

        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        Path path = file.toPath();
        Files.writeString(path, line, StandardCharsets.UTF_8);
        hide(file);
    }

    private void writeQuietly(Record r) {
        try {
            write(r);
        } catch (IOException ignored) {
            // A read-only credential file must not turn into a crash at the login prompt.
        }
    }

    private static void hide(File f) {
        try {
            new ProcessBuilder("attrib", "+h", f.getAbsolutePath())
                    .redirectErrorStream(true).start().waitFor();
        } catch (Exception ignored) {
            // cosmetic only
        }
    }

    // ------------------------------------------------------------- primitives

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Password hashing is unavailable on this system", e);
        }
    }

    /** HMAC that binds a record to this computer. */
    private static byte[] mac(String payload) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(machineKey(), "HmacSHA256"));
            return hmac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC is unavailable on this system", e);
        }
    }

    private static byte[] machineKey() throws Exception {
        String id = machineIdentity();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(("CheatGuard/admin-credential/v1/" + id).getBytes(StandardCharsets.UTF_8));
    }

    /** Windows MachineGuid, falling back to host and account names. */
    private static String machineIdentity() {
        try {
            Process p = new ProcessBuilder("reg", "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            int at = out.indexOf("REG_SZ");
            if (at > 0) {
                String guid = out.substring(at + 6).trim();
                int end = guid.indexOf('\n');
                if (end > 0) guid = guid.substring(0, end).trim();
                if (!guid.isEmpty()) return guid;
            }
        } catch (Exception ignored) {
            // fall through to the weaker identity below
        }
        return System.getenv("COMPUTERNAME") + "/" + System.getProperty("user.name");
    }
}
