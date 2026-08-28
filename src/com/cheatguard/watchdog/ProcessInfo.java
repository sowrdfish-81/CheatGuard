package com.cheatguard.watchdog;

/**
 * This class keeps basic information about a running process.
 */
public class ProcessInfo {

    // Unique process ID given by Windows
    private final long pid;

    // Name of the running process, for example chrome.exe
    private final String name;

    // Title of the visible application window
    private final String windowTitle;

    // Constructor to set process information
    public ProcessInfo(long pid, String name, String windowTitle) {
        this.pid = pid;
        this.name = name;
        this.windowTitle = windowTitle;
    }

    // Returns the process ID
    public long getPid() {
        return pid;
    }

    // Returns the process name
    public String getName() {
        return name;
    }

    // Returns the window title
    public String getWindowTitle() {
        return windowTitle;
    }

    // Makes the object easy to print and read in the console
    @Override
    public String toString() {
        return "ProcessInfo{" +
                "pid=" + pid +
                ", name='" + name + '\'' +
                ", windowTitle='" + windowTitle + '\'' +
                '}';
    }
}
