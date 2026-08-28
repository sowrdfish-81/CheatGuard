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

        // Get processes with a visible window
        // Output format: PID@@@ProcessName@@@WindowTitle
        String command =
                "Get-Process | " +
                "Where-Object { $_.MainWindowTitle -ne '' } | " +
                "ForEach-Object { " +
                "'{0}@@@{1}@@@{2}' -f $_.Id, $_.ProcessName, $_.MainWindowTitle " +
                "}";

        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
        );

        // Show PowerShell errors in the same output stream
        builder.redirectErrorStream(true);

        try {
            Process process = builder.start();

            // Read the PowerShell output line by line
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;

                while ((line = reader.readLine()) != null) {

                    line = line.trim();

                    if (line.isEmpty()) {
                        continue;
                    }

                    // Expected example:
                    // 1234@@@chrome@@@Google Chrome
                    String[] parts = line.split("@@@", 3);

                    if (parts.length != 3) {
                        System.out.println(
                                "PowerShell output: " + line
                        );
                        continue;
                    }

                    try {
                        long pid = Long.parseLong(parts[0].trim());

                        String name = parts[1].trim();
                        String windowTitle = parts[2].trim();

                        // Get-Process returns chrome instead of chrome.exe
                        if (!name.toLowerCase().endsWith(".exe")) {
                            name = name + ".exe";
                        }

                        ProcessInfo processInfo =
                                new ProcessInfo(pid, name, windowTitle);

                        processes.add(processInfo);

                    } catch (NumberFormatException e) {
                        System.out.println(
                                "Invalid process ID: " + parts[0]
                        );
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
