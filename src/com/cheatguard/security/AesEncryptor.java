package com.cheatguard.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * AES-256 encryption for sealed session logs (vault layer 2).
 *
 * <p>The administrator password is never used as a key directly. A 256-bit key is
 * derived with PBKDF2-HMAC-SHA256 using a random per-file salt and a high
 * iteration count, so two vaults sealed with the same password produce unrelated
 * keys and no precomputed table can be reused across files or installations.
 *
 * <p>The password travels as a {@code char[]} and is wiped from the key-spec as
 * soon as the key is derived; it is never held in a String, whose contents would
 * live in memory for an uncontrolled time.
 *
 * <p>File layout: {@code [16-byte salt][16-byte IV][ciphertext]}.
 */
public class AesEncryptor {

    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 16;
    private static final int ITERATIONS = 210_000;

    private SecretKeySpec deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    /** Read the plaintext log and write the encrypted vault file. */
    public void encryptFile(File plainFile, File encryptedOutFile, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(readAllBytes(plainFile));

        try (FileOutputStream fos = new FileOutputStream(encryptedOutFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(encrypted);
        }
    }

    public byte[] decryptFile(File encryptedFile, char[] password) throws Exception {
        byte[] fileBytes = readAllBytes(encryptedFile);
        int header = SALT_BYTES + IV_BYTES;
        if (fileBytes.length <= header) {
            throw new IllegalStateException("Vault file is truncated or not a Cheat.Guard vault.");
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(fileBytes, 0, salt, 0, SALT_BYTES);
        System.arraycopy(fileBytes, SALT_BYTES, iv, 0, IV_BYTES);

        byte[] cipherText = new byte[fileBytes.length - header];
        System.arraycopy(fileBytes, header, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    private byte[] readAllBytes(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
            }
            return bos.toByteArray();
        }
    }
}
