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
            // Packaged runs are elevated: launching directly would start the app as
            // ADMIN, which would bypass the student's file-access locks. Handing the
            // launch to Explorer starts it in the STUDENT's session instead. A
            // temporary shortcut carries the exam-folder argument and working dir.
            boolean elevatedRun = new File(
                    System.getProperty("jpackage.app-path", "")).isFile();
            if (elevatedRun) {
                File lnk = createStudentShortcut(executable, examFolder, name);
                if (lnk != null) {
                    new ProcessBuilder("explorer.exe", lnk.getAbsolutePath()).start();
                    return null;
                }
            }
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

    /**
     * Build a one-click shortcut in the exam folder that starts the approved app
     * with the exam folder as argument and working directory. The shortcut also
     * stays behind as a student-friendly launcher for the rest of the session.
     */
    private static File createStudentShortcut(File exe, File examFolder, String name) {
        try {
            File lnk = new File(examFolder, "Launch " + ProcessWhitelist.friendlyName(name) + ".lnk");
            String ps = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
                    + lnk.getAbsolutePath().replace("'", "''") + "');"
                    + "$s.TargetPath='" + exe.getAbsolutePath().replace("'", "''") + "';"
                    + (FOLDER_AWARE.contains(name)
                        ? "$s.Arguments='" + examFolder.getAbsolutePath().replace("'", "''") + "';"
                        : "")
                    + "$s.WorkingDirectory='" + examFolder.getAbsolutePath().replace("'", "''") + "';"
                    + "$s.Save()";
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", ps)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            return lnk.isFile() ? lnk : null;
        } catch (Exception e) {
            return null;
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
