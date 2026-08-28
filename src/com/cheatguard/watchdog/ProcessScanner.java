package com.cheatguard.watchdog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ProcessScanner {

    public List<ProcessInfo> scanProcesses() {

        // All scanned processes will be stored here
        List<ProcessInfo> processes = new ArrayList<>();

        // Get only the processes that have a visible window
        // and format the output so it is easier to parse in Java
        String command =
                "Get-Process | " +
                "Where-Object { $_.MainWindowTitle -ne '' } | " +
                "Select-Object Id, ProcessName, MainWindowTitle | " +
                "ForEach-Object { " +
                "\"$($_.Id)@@@$($_.ProcessName)@@@$($_.MainWindowTitle)\" " +
                "}";

        // Start PowerShell and run the process scanning command
        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe",
                "-NoProfile",
                "-Command",
                command
        );

        try {
            Process process = builder.start();

            // Read PowerShell output line by line
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;

                while ((line = reader.readLine()) != null) {

                    line = line.trim();

                    // Ignore empty lines from the command output
                    if (line.isEmpty()) {
                        continue;
                    }

                    // Output format:
                    // PID@@@ProcessName@@@WindowTitle
                    String[] parts = line.split("@@@", 3);

                    // Skip the line if the expected values are missing
                    if (parts.length < 3) {
                        continue;
                    }

                    try {
                        // Convert the process ID from text to long
                        long pid = Long.parseLong(parts[0].trim());

                        String name = parts[1].trim();

                        // Get-Process normally gives names without .exe
                        if (!name.toLowerCase().endsWith(".exe")) {
                            name = name + ".exe";
                        }

                        String windowTitle = parts[2].trim();

                        // Store the process information in a ProcessInfo object
                        ProcessInfo info =
                                new ProcessInfo(pid, name, windowTitle);

                        processes.add(info);

                    } catch (NumberFormatException e) {
                        // Ignore a process if the PID cannot be parsed
                        System.out.println(
                                "Invalid process ID: " + parts[0]
                        );
                    }
                }
            }

            // Wait until the PowerShell command finishes
            int exitCode = process.waitFor();

            if (exitCode != 0) {
                System.out.println(
                        "PowerShell process scan failed with exit code: "
                                + exitCode
                );
            }

        } catch (IOException e) {
            // Handles errors while starting or reading PowerShell
            System.out.println(
                    "Failed to run PowerShell process scan: "
                            + e.getMessage()
            );

        } catch (InterruptedException e) {
            // Restore the interrupt status if the thread gets interrupted
            Thread.currentThread().interrupt();

            System.out.println(
                    "Process scan was interrupted."
            );
        }

        // Return every process that was successfully read and parsed
        return processes;
    }
}
