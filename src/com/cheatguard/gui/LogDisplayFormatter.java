package com.cheatguard.gui;

import com.cheatguard.core.Violation;

import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Turns audit records into short rows an invigilator can read at a glance.
 *
 * <p>Rows carry a time, a status word and one plain sentence. Technical detail
 * (process ids, window titles, protocol names, full file paths) stays in the
 * stored record and is deliberately not shown.
 */
public final class LogDisplayFormatter {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private LogDisplayFormatter() {
    }

    public static String format(Violation v) {
        return row(v.getTimestamp().format(TIME), statusOf(v.getSeverity()),
                message(v.getType(), v.getDescription()));
    }

    /** Parse and format a stored log line (used by the admin dashboard). */
    public static String formatRaw(String line) {
        if (line == null || line.trim().isEmpty()) return "";
        String time = line.length() >= 19 ? line.substring(11, 19) : "--:--:--";
        String status = line.contains("[RED-FLAG]") ? "ALERT"
                : line.contains("[NOTICE]") ? "WARN" : "OK";
        String type = "EVENT";
        String detail = "";
        int sep = line.indexOf(" :: ");
        if (sep >= 0) {
            int dash = line.indexOf(" - ", sep + 4);
            if (dash >= 0) {
                type = line.substring(sep + 4, dash).trim();
                detail = line.substring(dash + 3).trim();
            } else {
                type = line.substring(sep + 4).trim();
            }
        } else {
            detail = line;
        }
        return row(time, status, message(type, detail));
    }

    /** Status word per severity: red flags are ALERTs, blocked attempts are WARN. */
    public static String statusOf(Violation.Severity severity) {
        return severity == Violation.Severity.WARNING || severity == Violation.Severity.CRITICAL
                ? "ALERT" : severity == Violation.Severity.NOTICE ? "WARN" : "OK";
    }

    private static String row(String time, String status, String text) {
        return String.format(Locale.ROOT, "%s   %-5s  %s", time, status, trim(text, 90));
    }

    /** One plain sentence per event type. */
    private static String message(String type, String rawDetail) {
        String d = clean(rawDetail);
        switch (type == null ? "" : type) {
            case "SESSION_START":
                return "Exam session started";
            case "SESSION_END":
                return "Exam session ended";
            case "STRICT_NETWORK_LOCK_ENABLED":
                return "Website lock is active";

            case "APP_CLOSED_AT_START":
                return "Closed before exam: " + orDefault(d, "an app");
            case "UNAUTHORIZED_APP_CLOSED":
                return "Not allowed, closed: " + orDefault(d, "an app");
            case "UNAUTHORIZED_APP_CLOSE_FAILED":
                return "Could not close: " + orDefault(d, "an app");
            case "ALLOWED_APP_OUTSIDE_FOLDER":
                return "Allowed app had a file outside the exam folder open, closed: "
                        + orDefault(d, "an app");
            case "ALLOWED_RUNTIME_OUTSIDE_FILE":
                return "Allowed program ran a file outside the exam folder, closed: "
                        + orDefault(d, "an app");
            case "ALLOWED_APP_OUTSIDE_FOLDER_SHOWN":
                return "Allowed app is showing content outside the exam folder: "
                        + orDefault(d, "an app");

            case "BLOCKED_INTERNET_DOMAIN":
                return "Website blocked: " + orDefault(d, "unknown site");

            case "UNAUTHORIZED_FOLDER_ACCESS":
                return "Opened outside exam folder: " + lastPathPart(d);

            case "EXTERNAL_DEVICE_PRESENT_AT_START":
                return "Device connected before exam: " + shortDevice(d);
            case "EXTERNAL_DEVICE_CONNECTED":
                return "Device plugged in: " + shortDevice(d);

            default:
                return d.isEmpty() ? readableType(type) : d;
        }
    }

    /** Strip any leftover "prefix" / "Key=value | ..." tail from older records. */
    private static String clean(String detail) {
        if (detail == null) return "";
        String s = detail.trim();
        int pipe = s.indexOf(" | ");
        if (pipe > 0) s = s.substring(0, pipe);
        for (String prefix : new String[]{
                "Blocked website: ", "Blocked app: ", "Closed at exam start: ",
                "Explorer opened outside exam folder: ", "Already connected when exam started: ",
                "Connected during exam: ", "Name resolution denied for unapproved domain: "}) {
            if (s.regionMatches(true, 0, prefix, 0, prefix.length())) {
                s = s.substring(prefix.length()).trim();
                break;
            }
        }
        return s.replaceAll("\\s+", " ").trim();
    }

    private static String orDefault(String s, String fallback) {
        return s.isEmpty() ? fallback : s;
    }

    /** Show only the folder name, not the whole path. */
    private static String lastPathPart(String path) {
        if (path.isEmpty()) return "a folder";
        String p = path.replace('/', '\\');
        while (p.endsWith("\\")) p = p.substring(0, p.length() - 1);
        int slash = p.lastIndexOf('\\');
        return slash >= 0 && slash < p.length() - 1 ? p.substring(slash + 1) : p;
    }

    /** Device records can be long ids; keep the readable head. */
    private static String shortDevice(String s) {
        if (s.isEmpty()) return "unknown device";
        String v = s;
        int bracket = v.indexOf(" [");
        if (bracket > 0) v = v.substring(0, bracket);
        return trim(v, 48);
    }

    private static String readableType(String type) {
        if (type == null || type.isBlank()) return "Event";
        String s = type.replace('_', ' ').toLowerCase(Locale.ROOT);
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    private static String trim(String value, int max) {
        if (value == null) return "";
        String s = value.replaceAll("\\s+", " ").trim();
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }
}
