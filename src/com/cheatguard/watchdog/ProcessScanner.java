package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Returns top-level visible Windows applications with PID, executable name and
 * window title.
 *
 * <p>Robustness rules baked in (learned the hard way in earlier builds):
 * the script is sent encoded so no shell quoting can corrupt it, output is read
 * as UTF-8 so window titles with special characters survive, the probe can never
 * hang longer than its timeout, and the child process is always destroyed so a
 * stuck PowerShell cannot leak on every watchdog cycle. On non-Windows systems
 * the scan returns an empty list instead of failing.
 */
public class ProcessScanner {

    private static final String FIELD_SEPARATOR = "@@@";
    private static final long COMMAND_TIMEOUT_SECONDS = 8;

    public List<ProcessInfo> getRunningProcesses() {
        List<ProcessInfo> out = new ArrayList<>();
        if (!isWindows()) return out;
        try {
            // $p.Path is the executable location; the watchdog uses it to tell the
            // student's own compiled work (built into the exam folder) from foreign apps.
            String command =
                    "Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | " +
                    "ForEach-Object { '{0}" + FIELD_SEPARATOR + "{1}" + FIELD_SEPARATOR + "{2}"
                            + FIELD_SEPARATOR + "{3}' -f " +
                            "$_.Id, $_.ProcessName, $_.MainWindowTitle, $_.Path }";
            Process process = PowerShellUtil.start(command);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.trim().split(FIELD_SEPARATOR, 4);
                    if (parts.length < 2) continue;
                    try {
                        long pid = Long.parseLong(parts[0].trim());
                        String name = parts[1].trim();
                        if (!name.toLowerCase(Locale.ROOT).endsWith(".exe")) name += ".exe";
                        String title = parts.length >= 3 ? parts[2].trim() : "";
                        String path = parts.length >= 4 ? parts[3].trim() : "";
                        out.add(new ProcessInfo(pid, name, title, "", path));
                    } catch (NumberFormatException ignored) {
                        // a garbled line must never abort the whole scan
                    }
                }
            }
            if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            AppLog.warn("Process scan error: " + e.getMessage());
        }
        return out;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
