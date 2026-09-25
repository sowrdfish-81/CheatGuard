package com.cheatguard.core;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** One exam session, its student folder, lifecycle times and audit log. */
public class ExamSession {
    private final String courseCode;
    private final String studentId;
    private final File examFolder;
    private final File sessionFile;
    private final LogManager logManager;
    private final LocalDateTime startTime;
    private LocalDateTime endTime;

    public ExamSession(String courseCode, String studentId) {
        this.courseCode = sanitize(courseCode);
        this.studentId = sanitize(studentId);
        this.examFolder = AppPaths.getExamFolder(this.studentId);
        this.startTime = LocalDateTime.now();

        File dir = AppPaths.getVaultDirectory();
        String stamp = startTime.format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        this.sessionFile = new File(dir, this.courseCode + "_Student" + this.studentId + "_" + stamp + ".dat");
        this.logManager = new LogManager(this.sessionFile);
        logManager.record(new Violation("SESSION_START",
                "Course=" + this.courseCode + " | StudentID=" + this.studentId +
                        " | ExamFolder=" + examFolder.getAbsolutePath(), Violation.Severity.INFO));
    }

    public synchronized void endSession() {
        if (endTime != null) return;
        endTime = LocalDateTime.now();
        long seconds = Math.max(0, Duration.between(startTime, endTime).getSeconds());
        logManager.record(new Violation("SESSION_END",
                "Course=" + courseCode + " | StudentID=" + studentId +
                        " | DurationSeconds=" + seconds, Violation.Severity.INFO));
    }

    private static String sanitize(String value) {
        String v = value == null ? "unknown" : value.trim();
        v = v.replaceAll("[^A-Za-z0-9._-]", "_");
        return v.isEmpty() ? "unknown" : v;
    }

    public String getSessionId() { return courseCode + " / " + studentId; }
    public String getCourseCode() { return courseCode; }
    public String getStudentId() { return studentId; }
    public File getExamFolder() { return examFolder; }
    public File getSessionFile() { return sessionFile; }
    public LogManager getLogManager() { return logManager; }
    public LocalDateTime getStartTime() { return startTime; }
    public LocalDateTime getEndTime() { return endTime; }
}
