package com.cheatguard.config;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Lists the applications INSTALLED on the computer by walking the Start Menu
 * shortcuts. A shortcut's file name is the app's real display name ("Visual
 * Studio Code.lnk"), and its target exe is resolved on demand with the
 * WScript.Shell COM object, so the walk stays fast even with hundreds of apps.
 */
public final class InstalledApps {

    /** One installed app found in the Start Menu. */
    public record App(String lnkPath, String displayName) {
    }

    private InstalledApps() {
    }

    /** Every Start Menu shortcut, sorted by display name, duplicates removed. */
    public static List<App> list() {
        Set<String> seen = new HashSet<>();
        List<App> apps = new ArrayList<>();
        for (String root : startMenuRoots()) {
            walk(new File(root), apps, seen, 0);
        }
        apps.sort((a, b) -> a.displayName().compareToIgnoreCase(b.displayName()));
        return apps;
    }

    /** Resolve the exe a shortcut points at (empty string when it cannot be read). */
    public static String resolveTarget(String lnkPath) {
        return resolveShortcut(lnkPath)[0];
    }

    /**
     * Resolve a shortcut into { targetPath, arguments }. The arguments matter for
     * Squirrel-style launchers - Discord's shortcut points at Update.exe with
     * "--processStart Discord.exe" - without which the launched updater does
     * nothing visible.
     */
    public static String[] resolveShortcut(String lnkPath) {
        String quoted = "'" + lnkPath.replace("'", "''") + "'";
        String script = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut(" + quoted + ");"
                + "Write-Output $s.TargetPath; Write-Output $s.Arguments";
        String[] out = {"", ""};
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", script)
                    .redirectErrorStream(true).start();
            String all = new String(p.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(15, TimeUnit.SECONDS);
            String[] lines = all.split("\\R");
            if (lines.length >= 1) out[0] = lines[0].trim();
            if (lines.length >= 2) out[1] = lines[1].trim();
            return out;
        } catch (Exception e) {
            return out;
        }
    }

    private static List<String> startMenuRoots() {
        List<String> roots = new ArrayList<>();
        String programData = System.getenv("ProgramData");
        if (programData != null && !programData.isBlank()) {
            roots.add(programData + "\\Microsoft\\Windows\\Start Menu\\Programs");
        }
        String appData = System.getenv("APPDATA");
        if (appData != null && !appData.isBlank()) {
            roots.add(appData + "\\Microsoft\\Windows\\Start Menu\\Programs");
        }
        return roots;
    }

    private static void walk(File dir, List<App> apps, Set<String> seen, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 5) return;
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File kid : new ArrayList<>(Arrays.asList(kids))) {
            String name = kid.getName();
            if (kid.isDirectory()) {
                walk(kid, apps, seen, depth + 1);
            } else if (name.toLowerCase(Locale.ROOT).endsWith(".lnk")) {
                String display = name.substring(0, name.length() - 4).trim();
                if (display.isEmpty() || !seen.add(display.toLowerCase(Locale.ROOT))) continue;
                apps.add(new App(kid.getAbsolutePath(), display));
            }
        }
    }
}
