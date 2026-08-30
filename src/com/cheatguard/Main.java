package com.cheatguard;

import com.cheatguard.watchdog.ProcessInfo;
import com.cheatguard.watchdog.ProcessScanner;

import java.util.List;

public class Main {

    public static void main(String[] args) {

        // Create the scanner
        ProcessScanner scanner = new ProcessScanner();

        // Scan running processes
        List<ProcessInfo> processes = scanner.getRunningProcesses();

        // Show how many processes were found
        System.out.println("Processes found: " + processes.size());

        // Print every process in the console
        for (ProcessInfo process : processes) {
            System.out.println(process);
        }
    }
}
