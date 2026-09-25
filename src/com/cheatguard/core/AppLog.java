package com.cheatguard.core;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Application diagnostics log, used by support tooling and the development team to
 * understand what happened on a machine after the fact.
 *
 * <p>Lines land in {@code <data>\logs\cheatguard-YYYY-MM-DD.log} and the console.
 * The packaged build has no console, so the file is the record; logs older than two
 * weeks are pruned automatically. Every writer failure is swallowed — diagnostics
 * must never break the application that is being diagnosed.
 */
public final class AppLog {

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final int KEEP_DAYS = 14;

    private AppLog() {
    }

    /** Route uncaught exceptions (worker threads and the Swing event thread) into the log. */
    public static void installCrashHandlers() {
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) ->
                write("ERROR", "Uncaught exception on thread '" + thread.getName() + "'", throwable));
        // Swing swallows EDT exceptions unless this legacy hook class is present.
        try {
            System.setProperty("sun.awt.exception.handler", EdtHandler.class.getName());
        } catch (Exception ignored) {
        }
    }

    /** Swing event-thread hook; instantiated reflectively by AWT. */
    public static final class EdtHandler {
        public EdtHandler() {
        }

        public void handle(Throwable throwable) {
            write("ERROR", "Exception on the Swing event thread", throwable);
        }
    }

    public static void info(String message) {
        write("INFO", message, null);
    }

    public static void warn(String message) {
        write("WARN", message, null);
    }

    public static void error(String message, Throwable throwable) {
        write("ERROR", message, throwable);
    }

    private static void write(String level, String message, Throwable throwable) {
        String line = LocalDateTime.now().format(STAMP) + " " + level + " " + message;
        if (throwable != null) {
            line += " :: " + throwable.getClass().getName() + ": " + throwable.getMessage();
            StackTraceElement[] stack = throwable.getStackTrace();
            if (stack.length > 0) line += " @ " + stack[0];
        }
        System.err.println(line); // visible in development; the file covers packaged builds
        try {
            File dir = new File(AppPaths.getDataDirectory(), "logs");
            if (!dir.exists()) dir.mkdirs();
            File file = new File(dir, "cheatguard-" + LocalDate.now() + ".log");
            boolean fresh = !file.isFile();
            Files.writeString(file.toPath(), line + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            if (fresh) prune(dir);
        } catch (Exception ignored) {
            // never let diagnostics break the app
        }
    }

    private static void prune(File dir) {
        File[] files = dir.listFiles((d, name) -> name.startsWith("cheatguard-") && name.endsWith(".log"));
        if (files == null) return;
        long cutoff = System.currentTimeMillis() - KEEP_DAYS * 24L * 3_600_000L;
        for (File f : files) {
            if (f.lastModified() < cutoff) {
                try {
                    Files.deleteIfExists(f.toPath());
                } catch (Exception ignored) {
                }
            }
        }
    }
}
