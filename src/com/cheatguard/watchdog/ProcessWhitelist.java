package com.cheatguard.watchdog;

import java.util.HashSet;
import java.util.Set;

/**
 * Keeps track of the processes that are allowed to run during an exam.
 */
public class ProcessWhitelist {

    // Stores the names of allowed processes.
    // Set automatically prevents duplicate process names.
    private final Set<String> allowedProcesses;

    /**
     * Creates an empty process whitelist.
     */
    public ProcessWhitelist() {
        allowedProcesses = new HashSet<>();
    }

    /**
     * Adds a process to the whitelist.
     *
     * @param processName name of the process
     */
    public void addProcess(String processName) {
        // Normalize the name before storing it.
        String normalizedName = normalizeProcessName(processName);

        allowedProcesses.add(normalizedName);
    }

    /**
     * Removes a process from the whitelist.
     *
     * @param processName name of the process
     */
    public void removeProcess(String processName) {
        // Normalize the name before removing it.
        String normalizedName = normalizeProcessName(processName);

        allowedProcesses.remove(normalizedName);
    }

    /**
     * Checks whether a process is allowed.
     *
     * @param processName name of the process
     * @return true if the process is in the whitelist
     */
    public boolean isAllowed(String processName) {
        // Normalize the name before checking.
        String normalizedName = normalizeProcessName(processName);

        return allowedProcesses.contains(normalizedName);
    }

    /**
     * Normalizes a process name by removing extra spaces
     * and converting it to lowercase.
     *
     * Example: " Chrome.EXE " becomes "chrome.exe".
     *
     * @param processName original process name
     * @return normalized process name
     */
    private String normalizeProcessName(String processName) {
        return processName.trim().toLowerCase();
    }
}
