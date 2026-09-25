package com.cheatguard.config;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Central locations for app data and per-student exam folders.
 *
 * <p>Machine data (the credential store, allowlists, sealed logs, network lockdown
 * state) lives under {@code %ProgramData%\CheatGuard}, not under a user profile.
 * The application always runs elevated, so files it creates there are owned by
 * Administrators while the signed-in student — a standard user — can read but not
 * write. This closes a family of attacks that the earlier per-profile layout
 * allowed: silently editing the website allowlist, deleting the credential file to
 * re-run first-time setup, forging the lockdown {@code stop.marker} to end the
 * session without the password, and swapping the elevated helper script while its
 * UAC prompt waited on screen (arbitrary code as administrator).
 *
 * <p>Development and tests can relocate everything with
 * {@code -Dcheatguard.data.dir=<path>}; the interactive (non-elevated) user's
 * profile, captured before elevation and passed back in, is only used to anchor
 * user-visible folders such as the per-student exam folder and the desktop
 * shortcut.
 */
public final class AppPaths {

    private static volatile String interactiveProfile;
    private static volatile String interactiveDesktop;

    private AppPaths() {
    }

    /**
     * Profile of the signed-in (interactive) user, passed by the launcher before
     * self-elevation. The elevated process may run as a different account, so
     * user-visible artifacts must anchor here rather than to the process owner.
     */
    public static void setInteractiveProfile(String profile) {
        if (profile != null && !profile.isBlank() && new File(profile).isDirectory()) {
            interactiveProfile = profile;
        }
    }

    /**
     * The signed-in user's real Desktop folder, captured by the launcher before
     * self-elevation. On machines where OneDrive redirects the Desktop, the plain
     * {@code <profile>\Desktop} path does not exist, so the exact known folder is
     * passed along instead of being guessed again in the elevated process.
     */
    public static void setInteractiveDesktop(String desktop) {
        if (desktop != null && !desktop.isBlank() && new File(desktop).isDirectory()) {
            interactiveDesktop = desktop;
        }
    }

    private static File interactiveProfileDirectory() {
        String p = interactiveProfile;
        if (p != null && !p.isBlank()) return new File(p);
        String userHome = System.getProperty("user.home");
        return userHome == null ? null : new File(userHome);
    }

    /** Root for all machine-wide app data. */
    public static File getDataDirectory() {
        String override = System.getProperty("cheatguard.data.dir");
        File base;
        if (override != null && !override.isBlank()) {
            base = new File(override);
        } else {
            String programData = System.getenv("ProgramData");
            if (programData != null && !programData.isBlank()) {
                base = new File(programData, "CheatGuard");
            } else {
                // Non-Windows development fallback.
                base = new File(System.getProperty("user.home"), ".cheatguard");
            }
        }
        if (!base.exists()) base.mkdirs();
        return base;
    }

    public static File getConfigDirectory() {
        File dir = new File(getDataDirectory(), "config");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getVaultDirectory() {
        File dir = new File(getDataDirectory(), "vault");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getNetworkDirectory() {
        File dir = new File(getDataDirectory(), "network");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getWhitelistFile() {
        return new File(getConfigDirectory(), "whitelist.properties");
    }

    /**
     * One-time migration from the older per-profile layout: copy existing
     * credentials, allowlists, sealed logs and any leftover lockdown state into the machine-wide directory so an
     * upgrade keeps working history. Best effort — old files are left in place.
     */
    public static void migrateLegacyProfileData() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) return;
        File legacy = new File(localAppData, "CheatGuard");
        if (!legacy.isDirectory()) return;
        copyTree(new File(legacy, "config"), getConfigDirectory());
        copyTree(new File(legacy, "vault"), getVaultDirectory());
        // A session left locked-down by an older per-profile build must remain
        // recoverable: migrating its state lets the new build's startup recovery
        // restore the machine's network automatically.
        copyTree(new File(legacy, "network"), getNetworkDirectory());
    }

    private static void copyTree(File from, File to) {
        if (!from.isDirectory()) return;
        File[] children = from.listFiles();
        if (children == null) return;
        for (File child : children) {
            File target = new File(to, child.getName());
            try {
                if (child.isDirectory()) {
                    copyTree(child, target);
                } else if (!target.exists()) {
                    Files.copy(child.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (Exception ignored) {
                // a failed copy of one legacy file must not stop the app
            }
        }
    }

    public static File getDesktopDirectory() {
        String captured = interactiveDesktop;
        if (captured != null) return new File(captured);
        File profile = interactiveProfileDirectory();
        if (profile != null) {
            File desktop = new File(profile, "Desktop");
            if (desktop.isDirectory()) return desktop;
        }
        try {
            File desktop = FileSystemView.getFileSystemView().getHomeDirectory();
            if (desktop != null && desktop.exists()) return desktop;
        } catch (Exception ignored) {
        }
        File fallback = interactiveProfileDirectory();
        return new File(fallback == null ? System.getProperty("user.home") : fallback.getAbsolutePath(), "Desktop");
    }

    public static File getExamFolder(String studentId) {
        String safe = sanitize(studentId);
        File folder = new File(getDesktopDirectory(), "Exam_" + safe);
        if (!folder.exists()) folder.mkdirs();
        return folder;
    }

    private static String sanitize(String value) {
        String v = value == null ? "unknown" : value.trim();
        v = v.replaceAll("[^A-Za-z0-9._-]", "_");
        return v.isEmpty() ? "unknown" : v;
    }
}
