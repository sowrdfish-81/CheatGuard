package com.cheatguard.watchdog;

/**
 * Immutable model that holds basic information about a running Windows process.
 *
 * Week 1 scope:
 *  - pid          : unique Windows process ID
 *  - name         : executable name, always lowercase with .exe suffix
 *  - windowTitle  : visible window title (empty string if none)
 */
public class ProcessInfo {

    private final long   pid;
    private final String name;
    private final String windowTitle;

    public ProcessInfo(long pid, String name, String windowTitle) {
        this.pid         = pid;
        // Null guard — prevents NullPointerException in Week 2 whitelist checks
        this.name        = (name == null)        ? "" : name.trim().toLowerCase();
        this.windowTitle = (windowTitle == null) ? "" : windowTitle.trim();
    }

    public long   getPid()         { return pid; }
    public String getName()        { return name; }
    public String getWindowTitle() { return windowTitle; }

    @Override
    public String toString() {
        return "ProcessInfo{"  +
               "pid="          + pid          +
               ", name='"      + name         + '\'' +
               ", windowTitle='" + windowTitle + '\'' +
               '}';
    }
}
