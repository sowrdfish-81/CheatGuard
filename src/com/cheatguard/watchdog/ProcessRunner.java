package com.cheatguard.watchdog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Runs a simple Windows command and reads its output.
 *
 * This class is mainly used to practice ProcessBuilder
 * before implementing the real ProcessScanner.
 */
public class ProcessRunner {

    /**
     * Runs "cmd /c echo Hello" and prints the output.
     */
    public void runTestCommand() {

        // ProcessBuilder is used to start an external
        // operating system command from Java.
        ProcessBuilder builder = new ProcessBuilder(
                "cmd", "/c", "echo", "Hello"
        );

        try {
            // Start the external process.
            Process process = builder.start();

            // Read the output produced by the command.
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );

            String line;

            // Read the command output line by line.
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // Wait until the command finishes.
            int exitCode = process.waitFor();

            // Exit code 0 normally means the command completed successfully.
            System.out.println("Exit code: " + exitCode);

        } catch (IOException e) {

            // Handles errors while starting the command
            // or reading its output.
            System.out.println("Could not run command: " + e.getMessage());

        } catch (InterruptedException e) {

            // Handles interruption while waiting for the process.
            System.out.println("Process was interrupted.");
            Thread.currentThread().interrupt();
        }
    }
}
