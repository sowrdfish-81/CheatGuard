package com.cheatguard.security;

import java.io.IOException;
import java.util.Arrays;

/**
 * Administrator authentication.
 *
 * <p>There is no built-in or default password: on first launch the administrator
 * chooses one and only a salted PBKDF2 digest is persisted by
 * {@link AdminCredentialStore}. Repeated wrong guesses are throttled, and the
 * plaintext is wiped from memory as soon as it has been used.
 */
public class AdminAuth {

    /** Minimum length accepted for a new administrator password. */
    public static final int MIN_LENGTH = 8;

    private final AdminCredentialStore store;

    public AdminAuth() {
        this(new AdminCredentialStore());
    }

    public AdminAuth(AdminCredentialStore store) {
        this.store = store;
    }

    /** False on a fresh installation, so the caller must run first-time setup. */
    public boolean isConfigured() {
        return store.isConfigured();
    }

    /** True when a credential file exists but was edited or copied from elsewhere. */
    public boolean isTampered() {
        return store.isTampered();
    }

    /**
     * Discard a credential file that failed its integrity check so first-time setup
     * can run again. The previous password is not recoverable, and session logs
     * sealed with it stay encrypted.
     */
    public void discardRejectedCredential() {
        if (store.isTampered()) {
            store.getFile().delete();
        }
    }

    /**
     * Create the administrator password on first run.
     *
     * @throws IllegalArgumentException if the password is too weak
     * @throws IllegalStateException    if one already exists
     */
    public void createPassword(char[] password) throws IOException {
        if (isConfigured()) {
            throw new IllegalStateException("An administrator password already exists.");
        }
        requireStrength(password);
        store.save(password);
        Arrays.fill(password, '\0');
    }

    /**
     * Verify a password, applying attempt throttling.
     *
     * <p>An empty submission is refused here without consulting the store: it costs
     * no PBKDF2 run and none of the five allowed attempts, matching the GUI rule
     * that a blank field is a mistake to correct, not a guessing attempt.
     * The array is wiped before returning either way.
     */
    public AdminCredentialStore.Result check(char[] password) {
        try {
            if (password == null || password.length == 0) {
                return AdminCredentialStore.Result.wrong(AdminCredentialStore.MAX_ATTEMPTS);
            }
            return store.verify(password);
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Replace the password after confirming the current one. */
    public void changePassword(char[] current, char[] next) throws IOException {
        AdminCredentialStore.Result result = store.verify(current);
        Arrays.fill(current, '\0');
        if (!result.success()) {
            throw new SecurityException(result.lockedForMs() > 0
                    ? "Too many failed attempts. Try again later."
                    : "The current administrator password is incorrect.");
        }
        requireStrength(next);
        store.save(next);
        Arrays.fill(next, '\0');
    }

    /**
     * Reject weak passwords. Length matters most for a PBKDF2-protected secret, so
     * the rule is a meaningful minimum length plus a mix of character classes.
     */
    public static void requireStrength(char[] password) {
        if (password == null || password.length < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters long.");
        }
        boolean letter = false;
        boolean other = false;
        for (char c : password) {
            if (Character.isLetter(c)) letter = true;
            else other = true;
        }
        if (!letter || !other) {
            throw new IllegalArgumentException(
                    "Password must mix letters with at least one number or symbol.");
        }
    }
}
