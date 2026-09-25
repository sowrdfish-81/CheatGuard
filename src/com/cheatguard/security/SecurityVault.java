package com.cheatguard.security;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Encryption/tamper facade for sealed logs plus admin-gated access/deletion.
 *
 * <p>Every method takes the administrator password as a {@code char[]} and wipes
 * its working copy before returning, so the plaintext password does not outlive
 * the call in a String or a leaked buffer.
 */
public class SecurityVault {
    private final FileLockManager lockManager = new FileLockManager();
    private final AesEncryptor encryptor = new AesEncryptor();
    private final Sha256Signer signer = new Sha256Signer();
    private final AdminAuth adminAuth;

    public SecurityVault(AdminAuth adminAuth) { this.adminAuth = adminAuth; }

    public boolean beginProtection(File plaintextLogFile) { return lockManager.lockFile(plaintextLogFile); }

    public void sealVault(File plaintextLogFile, char[] adminPassword) throws Exception {
        lockManager.releaseLock();
        requireAdmin(adminPassword);
        if (!plaintextLogFile.exists()) throw new IllegalStateException("Session log file is missing.");

        File vaultFile = new File(plaintextLogFile.getParent(), plaintextLogFile.getName().replace(".dat", ".vault"));
        encryptor.encryptFile(plaintextLogFile, vaultFile, adminPassword);
        String signature = signer.generateSignature(vaultFile);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        try (FileWriter fw = new FileWriter(sigFile)) { fw.write(signature); }

        if (!plaintextLogFile.delete()) plaintextLogFile.deleteOnExit();
        hideFile(vaultFile);
        hideFile(sigFile);
    }

    /** Opens a sealed .vault or an unsealed .dat left by a forced termination. */
    public String openLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null || !file.exists()) throw new IllegalArgumentException("Log file does not exist.");
        if (file.getName().toLowerCase().endsWith(".dat")) {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        }
        return openVault(file, adminPassword);
    }

    public String openVault(File vaultFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        if (!sigFile.exists()) throw new SecurityException("Signature file is missing.");
        String expectedSig = new String(Files.readAllBytes(sigFile.toPath()), StandardCharsets.UTF_8).trim();
        if (!signer.verify(vaultFile, expectedSig)) {
            throw new SecurityException("WARNING: log signature mismatch; file may have been tampered with.");
        }
        byte[] plain = encryptor.decryptFile(vaultFile, adminPassword);
        String content = new String(plain, StandardCharsets.UTF_8);
        Arrays.fill(plain, (byte) 0);
        return content;
    }

    /**
     * Delete a session log after checking the administrator password.
     *
     * <p>Sealed logs are owned by the Administrators group and are read-only for the
     * desktop account, so an ordinary delete is refused by Windows — that is exactly
     * what stops them being removed from Explorer. When the plain delete fails, the
     * request is repeated through an elevated helper, so deleting a log needs both the
     * administrator password here and a Windows permission prompt.
     */
    public void deleteLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null) return;

        java.util.List<File> targets = new java.util.ArrayList<>();
        targets.add(file);
        if (file.getName().toLowerCase().endsWith(".vault")) {
            File sig = new File(file.getAbsolutePath() + ".sig");
            if (sig.exists()) targets.add(sig);
        }

        boolean allGone = true;
        for (File target : targets) {
            if (target.exists() && !target.delete()) allGone = false;
        }
        if (allGone) return;

        if (!LogProtection.deleteElevated(targets)) {
            throw new IllegalStateException(
                    "Windows did not grant permission to delete this protected log.");
        }
        for (File target : targets) {
            if (target.exists()) {
                throw new IllegalStateException("The protected log could not be deleted.");
            }
        }
    }

    private void requireAdmin(char[] password) {
        // check() wipes the array it is given, so it must receive a copy - the
        // caller's array is still needed unchanged for the actual encryption.
        char[] probe = password == null ? new char[0] : password.clone();
        if (!adminAuth.check(probe).success()) {
            throw new SecurityException("Incorrect admin password.");
        }
    }

    private void hideFile(File file) {
        try {
            new ProcessBuilder("attrib", "+h", file.getAbsolutePath()).start().waitFor();
        } catch (Exception ignored) {
        }
    }
}
