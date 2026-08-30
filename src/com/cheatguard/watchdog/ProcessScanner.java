package com.cheatguard.watchdog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Reads visible Windows processes by executing PowerShell Get-Process.
 *
 * Fixes applied over the Week 1 draft:
 *  1. Renamed scanProcesses() → getRunningProcesses()  (matches Week 2 skeleton)
 *  2. Added 8-second timeout                           (prevents infinite hang)
 *  3. Added finally block to destroy leaked process    (no zombie OS processes)
 *  4. Added StandardCharsets.UTF_8                     (correct special-char titles)
 *  5. Added Windows-only guard                         (clean error on Mac/Linux)
 */
public class ProcessScanner {

    private static final String FIELD_SEPARATOR      = "@@@";
    private static final long   COMMAND_TIMEOUT_SECONDS = 8;

    /**
     * Returns visible top-level applications.
     * Returns an empty list on non-Windows systems or if the scan fails.
     */
    public List<ProcessInfo> getRunningProcesses() {

        List<ProcessInfo> processes = new ArrayList<>();

        // Fix 5 — Windows-only guard
        if (!isWindows()) {
            System.err.println("ProcessScanner supports Windows only.");
            return processes;
        }

        String command =
                "Get-Process | " +
                "Where-Object { $_.MainWindowTitle -ne '' } | " +
                "ForEach-Object { " +
                "'{0}" + FIELD_SEPARATOR + "{1}" + FIELD_SEPARATOR + "{2}'" +
                " -f $_.Id, $_.ProcessName, $_.MainWindowTitle " +
                "}";

        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
        );
        builder.redirectErrorStream(true);

        Process process = null;  // declared outside try so finally can reach it

        try {
            process = builder.start();

            // Fix 4 — UTF-8 charset so window titles with special characters are read correctly
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {

                String line;
                while ((line = reader.readLine()) != null) {

                    line = line.trim();
                    if (line.isEmpty()) continue;

                    String[] parts = line.split(FIELD_SEPARATOR, 3);

                    if (parts.length != 3) {
                        System.err.println("Unexpected PowerShell output: " + line);
                        continue;
                    }

                    try {
                        long   pid         = Long.parseLong(parts[0].trim());
                        String name        = parts[1].trim();
                        String windowTitle = parts[2].trim();

                        // Get-Process returns "chrome" — add .exe to match whitelist entries
                        if (!name.toLowerCase(Locale.ROOT).endsWith(".exe")) {
                            name = name + ".exe";
                        }

                        processes.add(new ProcessInfo(pid, name, windowTitle));

                    } catch (NumberFormatException e) {
                        System.err.println("Invalid process ID skipped: " + parts[0]);
                    }
                }
            }

            // Fix 2 — 8-second timeout instead of infinite waitFor()
            if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                System.err.println("Process scan timed out after " + COMMAND_TIMEOUT_SECONDS + "s.");
            } else if (process.exitValue() != 0) {
                System.err.println("PowerShell exited with code: " + process.exitValue());
            }

        } catch (IOException e) {
            System.err.println("Failed to start PowerShell: " + e.getMessage());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Process scan was interrupted.");

        } finally {
            // Fix 3 — always clean up the OS process to prevent leaks
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }

        return processes;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private boolean isWindows() {
        return System.getProperty("os.name", "")
                     .toLowerCase(Locale.ROOT)
                     .contains("win");
    }
}
