package com.cheatguard.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Sha256Signer: file-er content theke ekta SHA-256 "fingerprint" (hash)
 * ber kore. Ei hash ta alada .sig file e save rakha hoy (Layer 3 of vault).
 *
 * Kaje lage: jodi keu encrypted log file ta directly edit korar chesta kore
 * (tamper), tahole hash mile jabe na -> instructor dashboard bujhte parbe
 * je log ta tampered.
 */
public class Sha256Signer {

    public String generateSignature(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * @return true jodi file-er current hash, save kora signature-er shathe mile jai
     *         (mane file tampered hoyni)
     */
    public boolean verify(File file, String expectedSignature) throws IOException, NoSuchAlgorithmException {
        String actual = generateSignature(file);
        return actual.equalsIgnoreCase(expectedSignature);
    }
}
