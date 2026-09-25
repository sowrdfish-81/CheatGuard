package com.cheatguard.watchdog;

public class ProcessInfo {
    private final long pid;
    private final String name;
    private final String windowTitle;
    private final String browserUrl;
    private final String imagePath;

    public ProcessInfo(long pid, String name, String windowTitle) {
        this(pid, name, windowTitle, "", "");
    }

    public ProcessInfo(long pid, String name, String windowTitle, String browserUrl) {
        this(pid, name, windowTitle, browserUrl, "");
    }

    public ProcessInfo(long pid, String name, String windowTitle, String browserUrl, String imagePath) {
        this.pid = pid;
        this.name = name == null ? "" : name;
        this.windowTitle = windowTitle == null ? "" : windowTitle;
        this.browserUrl = browserUrl == null ? "" : browserUrl;
        this.imagePath = imagePath == null ? "" : imagePath;
    }
    public long getPid() { return pid; }
    public String getName() { return name; }
    public String getWindowTitle() { return windowTitle; }
    public String getBrowserUrl() { return browserUrl; }
    /** Full executable path when the scanner could read one, else empty. */
    public String getImagePath() { return imagePath; }
}
