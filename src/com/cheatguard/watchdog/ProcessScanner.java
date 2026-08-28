package com.cheatguard.watchdog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ProcessScanner {

    public List<ProcessInfo> scanProcesses() {

        // Store all detected processes here
        List<ProcessInfo> processes = new ArrayList<>();

        // Get processes that currently have a visible window
        // Format: PID@@@ProcessName@@@WindowTitle
        String command =
                "Get-Process | " +
                "Where-Object { $_.MainWindowTitle -ne '' } | " +
                "ForEach-Object { " +
                "\"$($_.Id)@@@$($_.ProcessName)@@@$($_.MainWindowTitle)\" " +
                "}";

        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-Command",
                command
        );

        // PowerShell errors will also come through the same stream
        builder.redirectErrorStream(true);

        try {
            Process process = builder.start();

            // Read PowerShell output line by line
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;

                while ((line = reader.readLine()) != null) {

                    line = line.trim();

                    if (line.isEmpty()) {
                        continue;
                    }

                    // Expected format:
                    // 1234@@@chrome@@@Google Chrome
                    String[] parts = line.split("@@@", 3);

                    if (parts.length != 3) {
                        continue;
                    }

                    try {
                        long pid = Long.parseLong(parts[0].trim());

                        String name = parts[1].trim();
                        String windowTitle = parts[2].trim();

                        // Get-Process returns names like chrome instead of chrome.exe
                        if (!name.toLowerCase().endsWith(".exe")) {
                            name = name + ".exe";
                        }

                        ProcessInfo info =
                                new ProcessInfo(pid, name, windowTitle);

                        processes.add(info);

                    } catch (NumberFormatException e) {
                        // Skip any line that does not contain a valid PID
                    }
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                System.out.println(
                        "PowerShell process scan failed with exit code: "
                                + exitCode
                );
            }

        } catch (IOException e) {
            System.out.println(
                    "Failed to run PowerShell: " + e.getMessage()
            );

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            System.out.println(
                    "Process scan was interrupted."
            );
        }

        return processes;
    }
}
