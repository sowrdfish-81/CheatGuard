package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Launches an approved application pointed at the student's exam folder.
 *
 * <p>The student never has to browse the disk to reach their workspace, which is
 * the point: the exam folder is the only folder they are meant to touch, and any
 * Explorer window opened somewhere else is reported by {@link FolderAccessMonitor}.
 */
public final class AllowedAppLauncher {

    /** Editors and IDEs that open a folder when it is passed as the first argument. */
    private static final List<String> FOLDER_AWARE = Arrays.asList(
            "code.exe", "code - insiders.exe", "codium.exe", "cursor.exe",
            "idea64.exe", "pycharm64.exe", "clion64.exe", "webstorm64.exe",
            "studio64.exe", "eclipse.exe", "subl.exe", "atom.exe", "devenv.exe");

    private AllowedAppLauncher() {
    }

    /**
     * Start an approved app on the exam folder.
     *
     * @return {@code null} on success, otherwise a message to show the invigilator
     */
    public static String launch(String appName, File examFolder) {
        if (appName == null || appName.isBlank()) return "No application selected.";
        String name = appName.trim().toLowerCase(Locale.ROOT);
        if (!name.endsWith(".exe")) name = name + ".exe";

        File executable = resolve(name);
        if (executable == null) {
            return "Could not find " + ProcessWhitelist.friendlyName(name) + " on this computer.\n"
                    + "Open \"Allowed apps and websites\" and add it again with \"Choose .exe\" "
                    + "so Cheat.Guard knows where it is installed.";
        }
        if (examFolder == null || !examFolder.isDirectory()) {
            return "The exam folder no longer exists.";
        }

        try {
            ProcessBuilder pb = FOLDER_AWARE.contains(name)
                    ? new ProcessBuilder(executable.getAbsolutePath(), examFolder.getAbsolutePath())
                    : new ProcessBuilder(executable.getAbsolutePath());
            // Even when the app ignores the argument, starting it here makes the exam
            // folder the default location in its open/save dialogs.
            pb.directory(examFolder);
            pb.redirectErrorStream(true);
            pb.start();
            return null;
        } catch (Exception e) {
            return "Could not start " + ProcessWhitelist.friendlyName(name) + ": " + e.getMessage();
        }
    }

    /** Stored path first, then PATH, then the usual Windows install locations. */
    private static File resolve(String name) {
        String stored = AppConfig.getInstance().getProcessPath(name);
        if (stored != null) {
            File f = new File(stored);
            if (f.isFile()) return f;
        }
        File onPath = fromWhere(name);
        if (onPath != null) return onPath;

        for (String base : new String[]{
                System.getenv("ProgramFiles"),
                System.getenv("ProgramFiles(x86)"),
                System.getenv("LOCALAPPDATA")}) {
            if (base == null || base.isBlank()) continue;
            File hit = searchShallow(new File(base), name, 0);
            if (hit != null) return hit;
        }
        return null;
    }

    private static File fromWhere(String name) {
        try {
            Process p = new ProcessBuilder("where", name).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            for (String line : out.split("\\R")) {
                File f = new File(line.trim());
                if (f.isFile()) return f;
            }
        } catch (Exception ignored) {
            // "where" is unavailable or found nothing
        }
        return null;
    }

    /** Look a few levels deep only; a full disk crawl would freeze the UI. */
    private static File searchShallow(File dir, String name, int depth) {
        if (depth > 3 || dir == null || !dir.isDirectory()) return null;
        File direct = new File(dir, name);
        if (direct.isFile()) return direct;
        File[] children = dir.listFiles(File::isDirectory);
        if (children == null) return null;
        for (File child : children) {
            File hit = searchShallow(child, name, depth + 1);
            if (hit != null) return hit;
        }
        return null;
    }
}
