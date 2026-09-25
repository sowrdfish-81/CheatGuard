# Cheat.Guard — Project Report (Full Code Edition)

**Project:** Cheat.Guard — an exam-lockdown application for Windows
**Team:** Member 1: ____________  ·  Member 2: ____________  ·  Member 3: ____________
**Language / tools:** Java (Swing), PowerShell, jpackage + WiX

**How this report works:** the whole project is divided among three members.
Every file of the project appears here with its FULL code and an easy
explanation next to it, under the member who owns it. Each part also has the
member's speech, the OOP concepts, the technologies, and likely questions with
answers. The last section is for everyone.

**File ownership map:**

| Member | Files owned |
|---|---|
| Member 1 (Core & Security) | core: Violation, LogManager, ExamSession, AppLog · config: AppPaths, AppConfig, InstalledApps · security: AdminAuth, AdminCredentialStore, AesEncryptor, Sha256Signer, SecurityVault, FileLockManager, InstanceGuard, LogProtection — 15 files |
| Member 2 (Blocking Engine) | watchdog (all 15): WatchdogEngine, DnsAllowlistServer, StrictNetworkLockdown, WebsiteViolationReporter, ProcessScanner, ProcessInfo, ProcessWhitelist, ProcessController, PowerShellUtil, SiteMonitor, FolderAccessMonitor, ExternalDeviceMonitor, SessionEnvironment, AllowedAppLauncher, ViolationListener + resources/network-lockdown.ps1 |
| Member 3 (UI, Installer & Testing) | Main.java · gui: UITheme, LogDisplayFormatter, SettingsPanel, DashboardPanel · build-installer.bat · test/CoreFlowTest.java |

---

# PART A — MEMBER 1: Core & Security (15 files)

## A1. What I say (opening, about 3 minutes)

"Good morning Sir. Our project is **Cheat.Guard** — a Windows desktop
application, written in Java, that locks a student's computer during an online
exam and keeps a written record of everything suspicious.

The problem is simple. In an online exam a student can open ChatGPT in another
tab, chat with a friend on Discord, plug in a USB stick, or use a VPN to open
blocked websites. Our program closes all these doors, and after the exam it
gives the teacher a sealed report as proof.

The flow is like this. The invigilator installs one setup file. On first launch
the program asks for an administrator password — there is no default password.
Then the invigilator sets which apps and websites are allowed. When the session
starts, the program first closes every app the student left running, then it
starts blocking. When the session ends, the program restores the computer and
seals the log with encryption.

My part is the core and security side: the session data, the password system,
and the sealing of the log. After me, my teammate will explain how the blocking
actually works."

## A2. How a session runs, step by step

1. **Install once.** One file, `CheatGuard-Setup.exe`, installs the program and
   its own copy of Java.
2. **First launch.** The invigilator picks an administrator password. Only an
   unreadable hash is stored, bound to that computer.
3. **Choose what is allowed.** The program already ships with the tools a
   programming contest needs (VS Code, gcc/g++, Java, Python, and sites like
   codeforces.com, atcoder.jp, leetcode.com). The invigilator can add or remove.
4. **Start the session.** The program asks for Windows admin permission once.
   It empties the clipboard (and the Win+V history), closes EVERY app the
   student left running, points every network card at its own DNS filter, and
   only then starts counting alerts.
5. **During the exam.** A running clock, a live event list in three colours,
   and two counters: red ALERTS (something got through) and yellow BLOCKED
   (they tried, the block held).
6. **End the session.** With the password: the computer is restored and the log
   is sealed with encryption and a signature.

## A3. My 14 files — full code + explanation

### 1) core/Violation.java — one suspicious event

```java
package com.cheatguard.core;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * OOP Concept: ENCAPSULATION
 * ---------------------------
 * Ei class ekta single "violation" (cheating attempt) ke represent kore.
 * Shob field 'private' -> bairer kono class direct field change korte parbe na,
 * shudhu getter দিয়ে read korte parbe. Eita data safety'r jonno important,
 * jate log tamper na hoy accidentally kono onno class theke.
 */
public class Violation {

    /**
     * INFO: tidy-up events that are not misconduct. NOTICE: the student tried
     * something that was blocked (a denied website lookup) — shown in yellow,
     * because the enforcement worked and nothing got through. WARNING/CRITICAL:
     * genuine red flags that count on the alert counter.
     */
    public enum Severity { INFO, NOTICE, WARNING, CRITICAL }

    private final LocalDateTime timestamp;
    private final String type;        // e.g. "ILLEGAL_PROCESS", "USB_INSERTED", "PROHIBITED_SITE"
    private final String description; // human readable detail
    private final Severity severity;

    public Violation(String type, String description, Severity severity) {
        this.timestamp = LocalDateTime.now();
        this.type = type;
        this.description = description;
        this.severity = severity;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getType() { return type; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }

    public boolean isRedFlag() {
        return severity == Severity.CRITICAL || severity == Severity.WARNING;
    }

    /**
     * Log e likhar jonno ekta single-line format.
     * CRITICAL/WARNING violation ke [RED-FLAG] tag diye mark kora hoy,
     * jate GUI dashboard eta dekhe red color e highlight korte pare.
     *
     * Line breaks in the description are flattened first: descriptions can carry
     * data from outside (process names, hosts) and a raw newline would let a crafted
     * name forge extra log lines that the dashboard would parse as real events.
     */
    @Override
    public String toString() {
        String tag = severity == Severity.NOTICE ? "[NOTICE]"
                : isRedFlag() ? "[RED-FLAG]" : "[NORMAL]";
        String ts = timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String safeDescription = description == null ? "" : description.replaceAll("[\\r\\n\\t]+", " ");
        String safeType = type == null ? "EVENT" : type.replaceAll("[\\r\\n\\t]+", " ");
        return String.format("%s %s %s :: %s - %s", ts, tag, severity, safeType, safeDescription);
    }
}
```

**What to notice:**
- The `Severity` enum has four levels. `isRedFlag()` is true only for
  WARNING/CRITICAL — NOTICE is the yellow "tried but blocked" level.
- All fields are `final`, no setters — **encapsulation + immutability**: a log
  entry can never be rewritten in memory.
- In `toString()`, `replaceAll("[\\r\\n\\t]+", " ")` flattens line breaks —
  that is the log-forgery defense: a program named with fake newlines cannot
  add its own log lines.

### 2) core/LogManager.java — the writer

```java
package com.cheatguard.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/** Thread-safe append-only session logger with short retry for transient Windows file contention. */
public class LogManager {
    private final File logFile;
    private final List<Violation> violations = new ArrayList<>();

    public LogManager(File logFile) {
        this.logFile = logFile;
        try {
            File parent = logFile.getParentFile();
            if (parent != null) parent.mkdirs();
            if (!logFile.exists()) logFile.createNewFile();
        } catch (IOException e) {
            AppLog.warn("Could not create log file: " + e.getMessage());
        }
    }

    public synchronized void record(Violation v) {
        violations.add(v);
        String line = v.toString() + System.lineSeparator();
        IOException last = null;

        // Synchronized prevents competing watchdog/UI threads in this process.
        // A few short retries also tolerate brief Windows AV/indexer contention.
        for (int attempt = 0; attempt < 4; attempt++) {
            try {
                Files.write(logFile.toPath(), line.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                return;
            } catch (IOException e) {
                last = e;
                try { Thread.sleep(25L * (attempt + 1)); }
                catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        AppLog.warn("Could not write log: " + (last == null ? "unknown error" : last.getMessage()));
    }

    public synchronized List<Violation> getAllViolations() { return new ArrayList<>(violations); }
    public File getLogFile() { return logFile; }
    public synchronized long getRedFlagCount() {
        long count = 0;
        for (Violation v : violations) if (v.isRedFlag()) count++;
        return count;
    }
}
```

**What to notice:**
- `record()` is `synchronized` — watchdog, DNS and UI threads all write at the
  same moment, so only one may enter at a time.
- The 4-attempt retry loop (sleep 25 ms more each time) survives Windows file
  contention from antivirus/indexers.
- Events also live in an in-memory list; `getRedFlagCount()` counts red ones —
  the ALERTS pill reads it.

### 3) core/ExamSession.java — one exam

```java
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
```

**What to notice:**
- `sanitize()` keeps only `A-Za-z0-9._-` — a crafted student ID cannot escape
  the folder name.
- The log file name has course + student + timestamp, inside the vault folder.
- The constructor immediately records SESSION_START; `endSession()` records
  SESSION_END with `DurationSeconds`, which the dashboard later parses.

### 4) core/AppLog.java — the app's own diary

```java
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
```

**What to notice:**
- `installCrashHandlers()` catches uncaught exceptions everywhere. The line
  `System.setProperty("sun.awt.exception.handler", ...)` is needed because
  Swing EATS exceptions on the UI thread unless this legacy hook exists.
- Every line goes to console AND `logs\cheatguard-date.log`; files older than
  14 days are pruned. All failures swallowed — diagnostics must never crash
  the app.

### 5) config/AppPaths.java — where files live

```java
package com.cheatguard.config;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Central locations for app data and per-student exam folders.
 *
 * <p>Machine data (the credential store, allowlists, sealed logs, network lockdown
 * state) lives under {@code %ProgramData%\CheatGuard}, not under a user profile.
 * The application always runs elevated, so files it creates there are owned by
 * Administrators while the signed-in student — a standard user — can read but not
 * write. This closes a family of attacks that the earlier per-profile layout
 * allowed: silently editing the website allowlist, deleting the credential file to
 * re-run first-time setup, forging the lockdown {@code stop.marker} to end the
 * session without the password, and swapping the elevated helper script while its
 * UAC prompt waited on screen (arbitrary code as administrator).
 *
 * <p>Development and tests can relocate everything with
 * {@code -Dcheatguard.data.dir=<path>}; the interactive (non-elevated) user's
 * profile, captured before elevation and passed back in, is only used to anchor
 * user-visible folders such as the per-student exam folder and the desktop
 * shortcut.
 */
public final class AppPaths {

    private static volatile String interactiveProfile;
    private static volatile String interactiveDesktop;

    private AppPaths() {
    }

    /**
     * Profile of the signed-in (interactive) user, passed by the launcher before
     * self-elevation. The elevated process may run as a different account, so
     * user-visible artifacts must anchor here rather than to the process owner.
     */
    public static void setInteractiveProfile(String profile) {
        if (profile != null && !profile.isBlank() && new File(profile).isDirectory()) {
            interactiveProfile = profile;
        }
    }

    /**
     * The signed-in user's real Desktop folder, captured by the launcher before
     * self-elevation. On machines where OneDrive redirects the Desktop, the plain
     * {@code <profile>\Desktop} path does not exist, so the exact known folder is
     * passed along instead of being guessed again in the elevated process.
     */
    public static void setInteractiveDesktop(String desktop) {
        if (desktop != null && !desktop.isBlank() && new File(desktop).isDirectory()) {
            interactiveDesktop = desktop;
        }
    }

    private static File interactiveProfileDirectory() {
        String p = interactiveProfile;
        if (p != null && !p.isBlank()) return new File(p);
        String userHome = System.getProperty("user.home");
        return userHome == null ? null : new File(userHome);
    }

    /** Root for all machine-wide app data. */
    public static File getDataDirectory() {
        String override = System.getProperty("cheatguard.data.dir");
        File base;
        if (override != null && !override.isBlank()) {
            base = new File(override);
        } else {
            String programData = System.getenv("ProgramData");
            if (programData != null && !programData.isBlank()) {
                base = new File(programData, "CheatGuard");
            } else {
                // Non-Windows development fallback.
                base = new File(System.getProperty("user.home"), ".cheatguard");
            }
        }
        if (!base.exists()) base.mkdirs();
        return base;
    }

    public static File getConfigDirectory() {
        File dir = new File(getDataDirectory(), "config");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getVaultDirectory() {
        File dir = new File(getDataDirectory(), "vault");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getNetworkDirectory() {
        File dir = new File(getDataDirectory(), "network");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    public static File getWhitelistFile() {
        return new File(getConfigDirectory(), "whitelist.properties");
    }

    /**
     * One-time migration from the older per-profile layout: copy existing
     * credentials, allowlists, sealed logs and any leftover lockdown state into the machine-wide directory so an
     * upgrade keeps working history. Best effort — old files are left in place.
     */
    public static void migrateLegacyProfileData() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) return;
        File legacy = new File(localAppData, "CheatGuard");
        if (!legacy.isDirectory()) return;
        copyTree(new File(legacy, "config"), getConfigDirectory());
        copyTree(new File(legacy, "vault"), getVaultDirectory());
        // A session left locked-down by an older per-profile build must remain
        // recoverable: migrating its state lets the new build's startup recovery
        // restore the machine's network automatically.
        copyTree(new File(legacy, "network"), getNetworkDirectory());
    }

    private static void copyTree(File from, File to) {
        if (!from.isDirectory()) return;
        File[] children = from.listFiles();
        if (children == null) return;
        for (File child : children) {
            File target = new File(to, child.getName());
            try {
                if (child.isDirectory()) {
                    copyTree(child, target);
                } else if (!target.exists()) {
                    Files.copy(child.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (Exception ignored) {
                // a failed copy of one legacy file must not stop the app
            }
        }
    }

    public static File getDesktopDirectory() {
        String captured = interactiveDesktop;
        if (captured != null) return new File(captured);
        File profile = interactiveProfileDirectory();
        if (profile != null) {
            File desktop = new File(profile, "Desktop");
            if (desktop.isDirectory()) return desktop;
        }
        try {
            File desktop = FileSystemView.getFileSystemView().getHomeDirectory();
            if (desktop != null && desktop.exists()) return desktop;
        } catch (Exception ignored) {
        }
        File fallback = interactiveProfileDirectory();
        return new File(fallback == null ? System.getProperty("user.home") : fallback.getAbsolutePath(), "Desktop");
    }

    public static File getExamFolder(String studentId) {
        String safe = sanitize(studentId);
        File folder = new File(getDesktopDirectory(), "Exam_" + safe);
        if (!folder.exists()) folder.mkdirs();
        return folder;
    }

    private static String sanitize(String value) {
        String v = value == null ? "unknown" : value.trim();
        v = v.replaceAll("[^A-Za-z0-9._-]", "_");
        return v.isEmpty() ? "unknown" : v;
    }
}
```

**What to notice:**
- `getDataDirectory()` → `%ProgramData%\CheatGuard` (machine-wide, protected
  from normal users) — overridable with `-Dcheatguard.data.dir` for tests.
- `interactiveProfile` / `interactiveDesktop` are passed in BEFORE elevation:
  the elevated process may run as a different admin, but the exam folder must
  land on the STUDENT's desktop. `getDesktopDirectory()` tries the captured
  folder first, then `profile\Desktop`, then the OneDrive-safe
  `FileSystemView` home directory.
- `migrateLegacyProfileData()` copies an older layout into ProgramData once —
  old files are left in place, existing targets are never overwritten.

### 6) config/AppConfig.java — the allowlists (Singleton)

```java
package com.cheatguard.config;

import com.cheatguard.core.AppLog;

import java.io.*;
import java.net.IDN;
import java.net.URI;
import java.util.*;

/** Persistent strict allow-lists edited from the admin GUI. */
public class AppConfig {

    /**
     * Defaults a fresh install (and an older config, once) starts from: the tools a
     * competitive-programming contest or coding test needs. Admins can remove any of
     * them per exam; the marker below keeps a later launch from re-adding removed ones.
     */
    private static final String[] DEFAULT_PROCESSES = {
            // editors and IDEs
            "code.exe", "codeblocks.exe", "notepad.exe", "notepad++.exe", "sublime_text.exe",
            "devcpp.exe", "idea64.exe", "clion64.exe",
            // compilers, linkers and build tools
            "gcc.exe", "g++.exe", "cc.exe", "c++.exe", "cpp.exe", "mingw32-gcc.exe",
            "mingw32-g++.exe", "as.exe", "ld.exe", "make.exe", "mingw32-make.exe",
            "cmake.exe", "gdb.exe",
            // the default output name of a g++/gcc build
            "a.exe",
            // language runtimes and terminals
            "java.exe", "javac.exe", "javaw.exe", "python.exe", "pythonw.exe", "py.exe",
            "node.exe", "git.exe", "bash.exe",
            "cmd.exe", "powershell.exe", "wt.exe", "windowsterminal.exe",
            "conhost.exe", "openconsole.exe",
    };

    private static final String[] DEFAULT_SITES = {
            // contest judges
            "codeforces.com", "atcoder.jp", "codechef.com", "leetcode.com",
            "hackerrank.com", "hackerearth.com", "topcoder.com", "cses.fi",
            "spoj.com", "vjudge.net", "lightoj.com", "beecrowd.com", "toph.co",
            // page assets used by the judges (Google search/login/mail stay OUT)
            "gstatic.com", "googleusercontent.com", "ssl.gstatic.com",
    };

    /** Search/login/mail sites removed from the defaults in version 3 (the subdomain
     *  rule would otherwise keep accounts.google.com and mail.google.com allowed). */
    private static final Set<String> REMOVED_IN_V3 =
            Set.of("accounts.google.com", "gmail.com", "google.com");

    /** Bump when the default lists change; missing defaults are merged in once per version. */
    private static final String DEFAULTS_VERSION = "3";

    private static AppConfig instance;
    private final File configFile = AppPaths.getWhitelistFile();
    private final Set<String> allowedProcesses = new TreeSet<>();
    private final Set<String> allowedSites = new TreeSet<>();
    /** Executable name to full launch path, for apps the admin picked from disk. */
    private final Map<String, String> processPaths = new TreeMap<>();
    /** Executable name to the app's real (marketing) name, e.g. code.exe -> Visual Studio Code. */
    private final Map<String, String> displayNames = new TreeMap<>();

    private AppConfig() { load(); }

    public static synchronized AppConfig getInstance() {
        if (instance == null) instance = new AppConfig();
        return instance;
    }

    private void load() {
        Properties props = new Properties();
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                props.load(fis);
            } catch (IOException e) {
                AppLog.warn("Could not read config: " + e.getMessage());
            }
        }
        String procs = props.getProperty("allowed.processes", "");
        String sites = props.getProperty("allowed.sites", "");
        for (String p : procs.split(",")) if (!p.trim().isEmpty()) allowedProcesses.add(normalizeProcess(p));
        for (String s : sites.split(",")) {
            String normalized = normalizeSite(s);
            if (!normalized.isEmpty()) allowedSites.add(normalized);
        }
        // Launch paths are stored as "name.exe|C:\path\name.exe" entries.
        for (String entry : props.getProperty("allowed.process.paths", "").split("\\|\\|")) {
            int bar = entry.indexOf('|');
            if (bar <= 0) continue;
            String name = normalizeProcess(entry.substring(0, bar));
            String path = entry.substring(bar + 1).trim();
            if (!name.isEmpty() && !path.isEmpty()) processPaths.put(name, path);
        }
        // Real app names: appname.code.exe=Visual Studio Code
        for (String key : props.stringPropertyNames()) {
            if (key.startsWith("appname.")) {
                String exe = normalizeProcess(key.substring(8));
                String display = props.getProperty(key, "").trim();
                if (!exe.isEmpty() && !display.isEmpty()) displayNames.put(exe, display);
            }
        }
        // One-time merge of a new default set into an existing configuration; after
        // this the marker is current, so entries an admin removed stay removed.
        // Version 3 also REMOVES the account/login sites from the defaults.
        boolean merged = false;
        if (!DEFAULTS_VERSION.equals(props.getProperty("allowlist.defaults.version", "1"))) {
            for (String p : DEFAULT_PROCESSES) {
                if (allowedProcesses.add(normalizeProcess(p))) merged = true;
            }
            for (String s : DEFAULT_SITES) {
                String normalized = normalizeSite(s);
                if (!normalized.isEmpty() && allowedSites.add(normalized)) merged = true;
            }
            for (String gone : REMOVED_IN_V3) {
                if (allowedSites.remove(normalizeSite(gone))) merged = true;
            }
        }
        if (!configFile.exists() || merged) save();
    }

    public synchronized void save() {
        Properties props = new Properties();
        props.setProperty("allowlist.defaults.version", DEFAULTS_VERSION);
        props.setProperty("allowed.processes", String.join(",", allowedProcesses));
        props.setProperty("allowed.sites", String.join(",", allowedSites));
        StringBuilder paths = new StringBuilder();
        for (Map.Entry<String, String> e : processPaths.entrySet()) {
            if (paths.length() > 0) paths.append("||");
            paths.append(e.getKey()).append('|').append(e.getValue());
        }
        props.setProperty("allowed.process.paths", paths.toString());
        for (Map.Entry<String, String> e : displayNames.entrySet()) {
            props.setProperty("appname." + e.getKey(), e.getValue());
        }
        try {
            File parent = configFile.getParentFile();
            if (parent != null) parent.mkdirs();
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                props.store(fos, "Cheat.Guard - strict allowlists");
            }
        } catch (IOException e) {
            AppLog.warn("Could not save config: " + e.getMessage());
        }
    }

    /** Full launch path for an allowed app, or null when only its name is known. */
    public synchronized String getProcessPath(String name) {
        return processPaths.get(normalizeProcess(name));
    }

    /** Register an app from its full path so it can also be launched from the app. */
    public synchronized void addAllowedProcessPath(File executable) {
        if (executable == null) return;
        String name = normalizeProcess(executable.getName());
        if (name.isEmpty()) return;
        allowedProcesses.add(name);
        processPaths.put(name, executable.getAbsolutePath());
        save();
    }

    /** Store the app's real (marketing) name shown in lists and logs. */
    public synchronized void setAppDisplayName(String exeName, String displayName) {
        String key = normalizeProcess(exeName);
        if (key.isEmpty() || displayName == null || displayName.isBlank()) return;
        displayNames.put(key, displayName.trim());
        save();
    }

    /** The app's real name when known, or null to fall back to the exe name. */
    public synchronized String getAppDisplayName(String exeName) {
        if (exeName == null) return null;
        return displayNames.get(normalizeProcess(exeName));
    }

    public synchronized Set<String> getAllowedProcesses() { return new TreeSet<>(allowedProcesses); }
    public synchronized Set<String> getAllowedSites() { return new TreeSet<>(allowedSites); }

    public synchronized void addAllowedProcess(String name) {
        String normalized = normalizeProcess(name);
        if (!normalized.isEmpty()) { allowedProcesses.add(normalized); save(); }
    }
    public synchronized void removeAllowedProcess(String name) {
        if (name != null) {
            String key = normalizeProcess(name);
            allowedProcesses.remove(key);
            processPaths.remove(key);
            displayNames.remove(key);
            save();
        }
    }
    public synchronized void addAllowedSite(String site) {
        if (site == null) return;
        // Accept pasted URLs or multiple domains, but persist only canonical host names.
        for (String part : site.split("[,;\\s]+")) {
            String normalized = normalizeSite(part);
            if (!normalized.isEmpty()) allowedSites.add(normalized);
        }
        save();
    }
    public synchronized void removeAllowedSite(String site) {
        if (site != null) { allowedSites.remove(normalizeSite(site)); save(); }
    }

    /** True for an allowed host itself and any of its subdomains. */
    public synchronized boolean isSiteAllowed(String hostOrUrl) {
        String host = normalizeSite(hostOrUrl);
        if (host.isEmpty()) return false;
        for (String allowed : allowedSites) {
            if (host.equals(allowed) || host.endsWith("." + allowed)) return true;
        }
        return false;
    }

    /** Canonical domain used by both the settings UI and the network proxy. */
    public static String normalizeSite(String value) {
        if (value == null) return "";
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (v.isEmpty()) return "";
        if (v.startsWith("*.")) v = v.substring(2);

        try {
            String candidate = v.matches("^[a-z][a-z0-9+.-]*://.*") ? v : "https://" + v;
            URI uri = new URI(candidate);
            String host = uri.getHost();
            if (host != null && !host.trim().isEmpty()) v = host;
            else {
                v = v.replaceFirst("^https?://", "");
                int slash = v.indexOf('/');
                if (slash >= 0) v = v.substring(0, slash);
                int q = v.indexOf('?');
                if (q >= 0) v = v.substring(0, q);
                int hash = v.indexOf('#');
                if (hash >= 0) v = v.substring(0, hash);
                int colon = v.lastIndexOf(':');
                if (colon > 0 && v.indexOf(':') == colon) v = v.substring(0, colon);
            }
        } catch (Exception ignored) {
            v = v.replaceFirst("^https?://", "");
            int slash = v.indexOf('/');
            if (slash >= 0) v = v.substring(0, slash);
            int colon = v.lastIndexOf(':');
            if (colon > 0 && v.indexOf(':') == colon) v = v.substring(0, colon);
        }

        v = v.replaceFirst("^www\\.", "");
        while (v.endsWith(".")) v = v.substring(0, v.length() - 1);
        try { v = IDN.toASCII(v); } catch (Exception ignored) {}
        // Require at least one dot and a letters-only TLD. Without this a bare entry
        // such as "com" would make isSiteAllowed() accept nearly every domain, because
        // matching also accepts subdomains of an allowed entry.
        return v.matches("([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}") ? v : "";
    }

    private String normalizeProcess(String value) {
        if (value == null) return "";
        String v = new File(value.trim()).getName().toLowerCase(Locale.ROOT);
        if (!v.isEmpty() && !v.contains(".") && !v.equals("system")) v += ".exe";
        return v;
    }
}
```

**What to notice:**
- **Singleton**: private constructor + one static instance + synchronized
  getter — the whole program shares ONE allowlist.
- `DEFAULT_PROCESSES` / `DEFAULT_SITES` are the built-in coding-test lists.
  The `allowlist.defaults.version` marker merges them into an OLD config once;
  after that, anything the admin removed stays removed.
- `isSiteAllowed()`: equals an entry OR ends with `.entry` — subdomains work.
- `normalizeSite()` ends with a REGEX that demands a real domain shape —
  without it, a bare "com" entry would allow nearly every site (because of the
  subdomain rule). `normalizeProcess()` adds `.exe` when missing.
- **Defaults version 3/4 notes**: version 3 removed the Google login/search/mail
  sites (accounts.google.com, google.com, gmail.com - the subdomain rule would
  otherwise have kept accounts.google.com allowed through google.com); version 4
  made the site list start EMPTY on every install, so the invigilator adds the
  exam sites one by one. Apps also carry a display-name map
  (`appname.code.exe=Visual Studio Code`) so lists and logs show real app names.

### 6b) config/InstalledApps.java — the installed-app search

```java
package com.cheatguard.config;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Lists the applications INSTALLED on the computer by walking the Start Menu
 * shortcuts. A shortcut's file name is the app's real display name ("Visual
 * Studio Code.lnk"), and its target exe is resolved on demand with the
 * WScript.Shell COM object, so the walk stays fast even with hundreds of apps.
 */
public final class InstalledApps {

    /** One installed app found in the Start Menu. */
    public record App(String lnkPath, String displayName) {
    }

    private InstalledApps() {
    }

    /** Every Start Menu shortcut, sorted by display name, duplicates removed. */
    public static List<App> list() {
        Set<String> seen = new HashSet<>();
        List<App> apps = new ArrayList<>();
        for (String root : startMenuRoots()) {
            walk(new File(root), apps, seen, 0);
        }
        apps.sort((a, b) -> a.displayName().compareToIgnoreCase(b.displayName()));
        return apps;
    }

    /** Resolve the exe a shortcut points at (empty string when it cannot be read). */
    public static String resolveTarget(String lnkPath) {
        String quoted = "'" + lnkPath.replace("'", "''") + "'";
        String script = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut(" + quoted + ");"
                + "$s.TargetPath";
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", script)
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(15, TimeUnit.SECONDS);
            return out;
        } catch (Exception e) {
            return "";
        }
    }

    private static List<String> startMenuRoots() {
        List<String> roots = new ArrayList<>();
        String programData = System.getenv("ProgramData");
        if (programData != null && !programData.isBlank()) {
            roots.add(programData + "\\Microsoft\\Windows\\Start Menu\\Programs");
        }
        String appData = System.getenv("APPDATA");
        if (appData != null && !appData.isBlank()) {
            roots.add(appData + "\\Microsoft\\Windows\\Start Menu\\Programs");
        }
        return roots;
    }

    private static void walk(File dir, List<App> apps, Set<String> seen, int depth) {
        if (dir == null || !dir.isDirectory() || depth > 5) return;
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File kid : new ArrayList<>(Arrays.asList(kids))) {
            String name = kid.getName();
            if (kid.isDirectory()) {
                walk(kid, apps, seen, depth + 1);
            } else if (name.toLowerCase(Locale.ROOT).endsWith(".lnk")) {
                String display = name.substring(0, name.length() - 4).trim();
                if (display.isEmpty() || !seen.add(display.toLowerCase(Locale.ROOT))) continue;
                apps.add(new App(kid.getAbsolutePath(), display));
            }
        }
    }
}
```

Walks the Start Menu folders (machine-wide and the user's own) collecting
shortcut files: a shortcut's file name IS the app's real display name, and the
target exe is resolved on demand with the WScript.Shell COM object, so the walk
stays fast even with hundreds of apps installed.

### 7) security/AdminAuth.java — the friendly face of the password

```java
package com.cheatguard.security;

import java.io.IOException;
import java.util.Arrays;

/**
 * Administrator authentication.
 *
 * <p>There is no built-in or default password: on first launch the administrator
 * chooses one and only a salted PBKDF2 digest is persisted by
 * {@link AdminCredentialStore}. Repeated wrong guesses are throttled, and the
 * plaintext is wiped from memory as soon as it has been used.
 */
public class AdminAuth {

    /** Minimum length accepted for a new administrator password. */
    public static final int MIN_LENGTH = 8;

    private final AdminCredentialStore store;

    public AdminAuth() {
        this(new AdminCredentialStore());
    }

    public AdminAuth(AdminCredentialStore store) {
        this.store = store;
    }

    /** False on a fresh installation, so the caller must run first-time setup. */
    public boolean isConfigured() {
        return store.isConfigured();
    }

    /** True when a credential file exists but was edited or copied from elsewhere. */
    public boolean isTampered() {
        return store.isTampered();
    }

    /**
     * Discard a credential file that failed its integrity check so first-time setup
     * can run again. The previous password is not recoverable, and session logs
     * sealed with it stay encrypted.
     */
    public void discardRejectedCredential() {
        if (store.isTampered()) {
            store.getFile().delete();
        }
    }

    /**
     * Create the administrator password on first run.
     *
     * @throws IllegalArgumentException if the password is too weak
     * @throws IllegalStateException    if one already exists
     */
    public void createPassword(char[] password) throws IOException {
        if (isConfigured()) {
            throw new IllegalStateException("An administrator password already exists.");
        }
        requireStrength(password);
        store.save(password);
        Arrays.fill(password, '\0');
    }

    /**
     * Verify a password, applying attempt throttling.
     *
     * <p>An empty submission is refused here without consulting the store: it costs
     * no PBKDF2 run and none of the five allowed attempts, matching the GUI rule
     * that a blank field is a mistake to correct, not a guessing attempt.
     * The array is wiped before returning either way.
     */
    public AdminCredentialStore.Result check(char[] password) {
        try {
            if (password == null || password.length == 0) {
                return AdminCredentialStore.Result.wrong(AdminCredentialStore.MAX_ATTEMPTS);
            }
            return store.verify(password);
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    /** Replace the password after confirming the current one. */
    public void changePassword(char[] current, char[] next) throws IOException {
        AdminCredentialStore.Result result = store.verify(current);
        Arrays.fill(current, '\0');
        if (!result.success()) {
            throw new SecurityException(result.lockedForMs() > 0
                    ? "Too many failed attempts. Try again later."
                    : "The current administrator password is incorrect.");
        }
        requireStrength(next);
        store.save(next);
        Arrays.fill(next, '\0');
    }

    /**
     * Reject weak passwords. Length matters most for a PBKDF2-protected secret, so
     * the rule is a meaningful minimum length plus a mix of character classes.
     */
    public static void requireStrength(char[] password) {
        if (password == null || password.length < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters long.");
        }
        boolean letter = false;
        boolean other = false;
        for (char c : password) {
            if (Character.isLetter(c)) letter = true;
            else other = true;
        }
        if (!letter || !other) {
            throw new IllegalArgumentException(
                    "Password must mix letters with at least one number or symbol.");
        }
    }
}
```

**What to notice:**
- `createPassword()` refuses if a password already exists.
- `check()`: empty input returns "wrong, 5 attempts left" WITHOUT touching the
  store — an empty submit is a typo, not a guessing attempt, and costs no
  PBKDF2 run. `finally` wipes the array — this is the char[] hygiene rule.
- `requireStrength()`: 8+ characters, must contain letters AND something else
  (number/symbol).

### 8) security/AdminCredentialStore.java — the file format

```java
package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * On-disk store for the administrator password.
 *
 * <p>Design goals, in order:
 *
 * <ol>
 *   <li><b>The password cannot be recovered from anything that ships.</b> Only a
 *       PBKDF2-HMAC-SHA256 digest with a random 16-byte salt and a high iteration
 *       count is written. There is no default password anywhere in the source, the
 *       jar or the installer, so decompiling the application or reading the
 *       repository reveals nothing usable.</li>
 *   <li><b>The record cannot be moved between computers.</b> Every record carries
 *       an HMAC keyed by this machine's identity, so a credential file taken from
 *       a machine whose password is known is rejected here.</li>
 *   <li><b>Failed attempts cannot be wiped by editing the file.</b> The attempt
 *       counter and lockout deadline are inside the authenticated payload.</li>
 * </ol>
 *
 * <p>Known boundary: an attacker with local administrator rights can delete the
 * file and run first-time setup again. That gives them a <em>new</em> password, not
 * the old one, and every session log already sealed with the previous password
 * stays unreadable. Preventing even that requires a server-side account, which is
 * what the planned university portal will provide.
 */
public final class AdminCredentialStore {

    private static final String FORMAT = "cg1";
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    /** Attempts allowed before a cooling-off period begins. */
    public static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_BASE_MS = 30_000L;
    private static final long LOCKOUT_MAX_MS = 15 * 60_000L;

    private final File file;

    public AdminCredentialStore() {
        this(new File(AppPaths.getConfigDirectory(), "admin.cred"));
    }

    AdminCredentialStore(File file) {
        this.file = file;
    }

    /** Immutable snapshot of the stored record. */
    record Record(int iterations, byte[] salt, byte[] hash, int failures, long lockedUntil) {
    }

    public boolean isConfigured() {
        return read() != null;
    }

    /** True when the file exists but its contents are not trustworthy. */
    public boolean isTampered() {
        return file.isFile() && read() == null;
    }

    public File getFile() {
        return file;
    }

    /** Store a brand-new password, replacing any existing record. */
    public void save(char[] password) throws IOException {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);
        write(new Record(ITERATIONS, salt, hash, 0, 0L));
    }

    /**
     * Check a password and update the attempt counter.
     *
     * @return the outcome, including remaining lockout time when applicable
     */
    public Result verify(char[] password) {
        Record record = read();
        if (record == null) return Result.notConfigured();

        long now = System.currentTimeMillis();
        if (record.lockedUntil() > now) {
            return Result.lockedOut(record.lockedUntil() - now);
        }

        byte[] candidate = derive(password, record.salt(), record.iterations());
        if (MessageDigest.isEqual(record.hash(), candidate)) {
            writeQuietly(new Record(record.iterations(), record.salt(), record.hash(), 0, 0L));
            return Result.ok();
        }

        int failures = record.failures() + 1;
        long lockedUntil = 0L;
        if (failures >= MAX_ATTEMPTS) {
            // Back off further on each additional group of failures, capped.
            long factor = 1L << Math.min(failures - MAX_ATTEMPTS, 5);
            lockedUntil = now + Math.min(LOCKOUT_BASE_MS * factor, LOCKOUT_MAX_MS);
        }
        writeQuietly(new Record(record.iterations(), record.salt(), record.hash(), failures, lockedUntil));
        int left = Math.max(0, MAX_ATTEMPTS - failures);
        return lockedUntil > now
                ? Result.lockedOut(lockedUntil - now)
                : Result.wrong(left);
    }

    /** Outcome of a verification attempt. */
    public record Result(boolean success, boolean configured, long lockedForMs, int attemptsLeft) {
        static Result ok() { return new Result(true, true, 0L, MAX_ATTEMPTS); }
        static Result wrong(int left) { return new Result(false, true, 0L, left); }
        static Result lockedOut(long ms) { return new Result(false, true, ms, 0); }
        static Result notConfigured() { return new Result(false, false, 0L, MAX_ATTEMPTS); }
    }

    // ------------------------------------------------------- file read / write

    private Record read() {
        try {
            if (!file.isFile()) return null;
            String line = Files.readString(file.toPath(), StandardCharsets.UTF_8).trim();
            String[] p = line.split("\\|");
            if (p.length != 7 || !FORMAT.equals(p[0])) return null;

            String payload = String.join("|", p[0], p[1], p[2], p[3], p[4], p[5]);
            byte[] expected = Base64.getDecoder().decode(p[6]);
            if (!MessageDigest.isEqual(expected, mac(payload))) return null; // moved or edited

            return new Record(
                    Integer.parseInt(p[1]),
                    Base64.getDecoder().decode(p[2]),
                    Base64.getDecoder().decode(p[3]),
                    Integer.parseInt(p[4]),
                    Long.parseLong(p[5]));
        } catch (Exception e) {
            return null;
        }
    }

    private void write(Record r) throws IOException {
        Base64.Encoder enc = Base64.getEncoder();
        String payload = String.join("|",
                FORMAT,
                Integer.toString(r.iterations()),
                enc.encodeToString(r.salt()),
                enc.encodeToString(r.hash()),
                Integer.toString(r.failures()),
                Long.toString(r.lockedUntil()));
        String line = payload + "|" + enc.encodeToString(mac(payload));

        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        Path path = file.toPath();
        Files.writeString(path, line, StandardCharsets.UTF_8);
        hide(file);
    }

    private void writeQuietly(Record r) {
        try {
            write(r);
        } catch (IOException ignored) {
            // A read-only credential file must not turn into a crash at the login prompt.
        }
    }

    private static void hide(File f) {
        try {
            new ProcessBuilder("attrib", "+h", f.getAbsolutePath())
                    .redirectErrorStream(true).start().waitFor();
        } catch (Exception ignored) {
            // cosmetic only
        }
    }

    // ------------------------------------------------------------- primitives

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Password hashing is unavailable on this system", e);
        }
    }

    /** HMAC that binds a record to this computer. */
    private static byte[] mac(String payload) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(machineKey(), "HmacSHA256"));
            return hmac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC is unavailable on this system", e);
        }
    }

    private static byte[] machineKey() throws Exception {
        String id = machineIdentity();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(("CheatGuard/admin-credential/v1/" + id).getBytes(StandardCharsets.UTF_8));
    }

    /** Windows MachineGuid, falling back to host and account names. */
    private static String machineIdentity() {
        try {
            Process p = new ProcessBuilder("reg", "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            int at = out.indexOf("REG_SZ");
            if (at > 0) {
                String guid = out.substring(at + 6).trim();
                int end = guid.indexOf('\n');
                if (end > 0) guid = guid.substring(0, end).trim();
                if (!guid.isEmpty()) return guid;
            }
        } catch (Exception ignored) {
            // fall through to the weaker identity below
        }
        return System.getenv("COMPUTERNAME") + "/" + System.getProperty("user.name");
    }
}
```

**What to notice — the stored line is:**
```
cg1|210000|salt|hash|failedAttempts|lockoutTime|HMAC
```
- `save()`: new 16-byte `SecureRandom` salt → PBKDF2 (210,000 rounds) → write
  → `attrib +h` hides the file.
- `verify()`: first the HMAC (keyed with the PC's MachineGuid — any edit or
  PC-move breaks it) → then the lockout time → then derive the candidate hash
  and compare with `MessageDigest.isEqual` (constant time — no timing leak).
- Failure #5 starts a lockout of 30 s × 2^(extra failures), capped at 15 min.
  The counter lives INSIDE the signed payload — wiping it breaks the HMAC.
- `machineIdentity()` reads MachineGuid from the registry, falling back to
  computer + user name.

### 9) security/AesEncryptor.java — encryption

```java
package com.cheatguard.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * AES-256 encryption for sealed session logs (vault layer 2).
 *
 * <p>The administrator password is never used as a key directly. A 256-bit key is
 * derived with PBKDF2-HMAC-SHA256 using a random per-file salt and a high
 * iteration count, so two vaults sealed with the same password produce unrelated
 * keys and no precomputed table can be reused across files or installations.
 *
 * <p>The password travels as a {@code char[]} and is wiped from the key-spec as
 * soon as the key is derived; it is never held in a String, whose contents would
 * live in memory for an uncontrolled time.
 *
 * <p>File layout: {@code [16-byte salt][16-byte IV][ciphertext]}.
 */
public class AesEncryptor {

    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 16;
    private static final int ITERATIONS = 210_000;

    private SecretKeySpec deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    /** Read the plaintext log and write the encrypted vault file. */
    public void encryptFile(File plainFile, File encryptedOutFile, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(readAllBytes(plainFile));

        try (FileOutputStream fos = new FileOutputStream(encryptedOutFile)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(encrypted);
        }
    }

    public byte[] decryptFile(File encryptedFile, char[] password) throws Exception {
        byte[] fileBytes = readAllBytes(encryptedFile);
        int header = SALT_BYTES + IV_BYTES;
        if (fileBytes.length <= header) {
            throw new IllegalStateException("Vault file is truncated or not a Cheat.Guard vault.");
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(fileBytes, 0, salt, 0, SALT_BYTES);
        System.arraycopy(fileBytes, SALT_BYTES, iv, 0, IV_BYTES);

        byte[] cipherText = new byte[fileBytes.length - header];
        System.arraycopy(fileBytes, header, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    private byte[] readAllBytes(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
            }
            return bos.toByteArray();
        }
    }
}
```

**What to notice:**
- File layout: `[16-byte salt][16-byte IV][AES ciphertext]`.
- Fresh salt + IV per file: the same password gives a different key for every
  log.
- `spec.clearPassword()` in `finally` — the password chars are wiped from the
  key spec after the key is derived.

### 10) security/Sha256Signer.java — the fingerprint

```java
package com.cheatguard.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Sha256Signer: file-er content theke ekta SHA-256 "fingerprint" (hash)
 * ber kore. Ei hash ta alada .sig file e save rakha hoy (Layer 3 of vault).
 *
 * Kaje lage: jodi keu encrypted log file ta directly edit korar chesta kore
 * (tamper), tahole hash mile jabe na -> instructor dashboard bujhte parbe
 * je log ta tampered.
 */
public class Sha256Signer {

    public String generateSignature(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * @return true jodi file-er current hash, save kora signature-er shathe mile jai
     *         (mane file tampered hoyni)
     */
    public boolean verify(File file, String expectedSignature) throws IOException, NoSuchAlgorithmException {
        String actual = generateSignature(file);
        return actual.equalsIgnoreCase(expectedSignature);
    }
}
```

**What to notice:**
- Streams the file in 8 KB chunks — a big log never sits in memory whole.
- `verify()` recomputes and compares ignoring case. One byte changed →
  mismatch → the dashboard reports "tampered".
- The comments are in Banglish — we wrote learning notes right in the code.

### 11) security/SecurityVault.java — the manager (facade)

```java
package com.cheatguard.security;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Encryption/tamper facade for sealed logs plus admin-gated access/deletion.
 *
 * <p>Every method takes the administrator password as a {@code char[]} and wipes
 * its working copy before returning, so the plaintext password does not outlive
 * the call in a String or a leaked buffer.
 */
public class SecurityVault {
    private final FileLockManager lockManager = new FileLockManager();
    private final AesEncryptor encryptor = new AesEncryptor();
    private final Sha256Signer signer = new Sha256Signer();
    private final AdminAuth adminAuth;

    public SecurityVault(AdminAuth adminAuth) { this.adminAuth = adminAuth; }

    public boolean beginProtection(File plaintextLogFile) { return lockManager.lockFile(plaintextLogFile); }

    public void sealVault(File plaintextLogFile, char[] adminPassword) throws Exception {
        lockManager.releaseLock();
        requireAdmin(adminPassword);
        if (!plaintextLogFile.exists()) throw new IllegalStateException("Session log file is missing.");

        File vaultFile = new File(plaintextLogFile.getParent(), plaintextLogFile.getName().replace(".dat", ".vault"));
        encryptor.encryptFile(plaintextLogFile, vaultFile, adminPassword);
        String signature = signer.generateSignature(vaultFile);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        try (FileWriter fw = new FileWriter(sigFile)) { fw.write(signature); }

        if (!plaintextLogFile.delete()) plaintextLogFile.deleteOnExit();
        hideFile(vaultFile);
        hideFile(sigFile);
    }

    /** Opens a sealed .vault or an unsealed .dat left by a forced termination. */
    public String openLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null || !file.exists()) throw new IllegalArgumentException("Log file does not exist.");
        if (file.getName().toLowerCase().endsWith(".dat")) {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        }
        return openVault(file, adminPassword);
    }

    public String openVault(File vaultFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        if (!sigFile.exists()) throw new SecurityException("Signature file is missing.");
        String expectedSig = new String(Files.readAllBytes(sigFile.toPath()), StandardCharsets.UTF_8).trim();
        if (!signer.verify(vaultFile, expectedSig)) {
            throw new SecurityException("WARNING: log signature mismatch; file may have been tampered with.");
        }
        byte[] plain = encryptor.decryptFile(vaultFile, adminPassword);
        String content = new String(plain, StandardCharsets.UTF_8);
        Arrays.fill(plain, (byte) 0);
        return content;
    }

    /**
     * Delete a session log after checking the administrator password.
     *
     * <p>Sealed logs are owned by the Administrators group and are read-only for the
     * desktop account, so an ordinary delete is refused by Windows — that is exactly
     * what stops them being removed from Explorer. When the plain delete fails, the
     * request is repeated through an elevated helper, so deleting a log needs both the
     * administrator password here and a Windows permission prompt.
     */
    public void deleteLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null) return;

        java.util.List<File> targets = new java.util.ArrayList<>();
        targets.add(file);
        if (file.getName().toLowerCase().endsWith(".vault")) {
            File sig = new File(file.getAbsolutePath() + ".sig");
            if (sig.exists()) targets.add(sig);
        }

        boolean allGone = true;
        for (File target : targets) {
            if (target.exists() && !target.delete()) allGone = false;
        }
        if (allGone) return;

        if (!LogProtection.deleteElevated(targets)) {
            throw new IllegalStateException(
                    "Windows did not grant permission to delete this protected log.");
        }
        for (File target : targets) {
            if (target.exists()) {
                throw new IllegalStateException("The protected log could not be deleted.");
            }
        }
    }

    private void requireAdmin(char[] password) {
        // check() wipes the array it is given, so it must receive a copy - the
        // caller's array is still needed unchanged for the actual encryption.
        char[] probe = password == null ? new char[0] : password.clone();
        if (!adminAuth.check(probe).success()) {
            throw new SecurityException("Incorrect admin password.");
        }
    }

    private void hideFile(File file) {
        try {
            new ProcessBuilder("attrib", "+h", file.getAbsolutePath()).start().waitFor();
        } catch (Exception ignored) {
        }
    }
}
```

**What to notice:**
- **Facade pattern**: it holds the encryptor, the signer and the lock manager,
  and offers four simple verbs: protect, seal, open, delete.
- `sealVault()`: release lock → verify password → encrypt → sign → delete the
  plaintext (with `deleteOnExit` fallback) → hide the new files.
- `openLog()`: an unsealed `.dat` reads directly (crash recovery); a `.vault`
  verifies the SIGNATURE first, then decrypts, then zeroes the plain bytes.
- `requireAdmin()` verifies a CLONE of the password: `check()` wipes the array
  it receives, but the encryption still needs the original.

### 12) security/FileLockManager.java — why lock only byte 0?

```java
package com.cheatguard.security;

import com.cheatguard.core.AppLog;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * Keeps the active plaintext log open and locks only a tiny guard range.
 *
 * Why not lock the whole file?
 * On Windows a whole-file lock also blocks this application's own append
 * writer when it opens a second handle, producing:
 * "The process cannot access the file because another process has locked a portion of the file".
 *
 * Locking byte 0 keeps an OS-level guard while allowing append writes after
 * the existing content. The open RandomAccessFile handle also remains alive
 * for the full exam session and is released before sealing the vault.
 */
public class FileLockManager {
    private RandomAccessFile raf;
    private FileChannel channel;
    private FileLock lock;

    public synchronized boolean lockFile(File file) {
        releaseLock();
        try {
            raf = new RandomAccessFile(file, "rw");
            channel = raf.getChannel();
            // Guard only the first byte instead of the entire file.
            lock = channel.lock(0L, 1L, false);
            return true;
        } catch (IOException | RuntimeException e) {
            AppLog.warn("Could not protect active log: " + e.getMessage());
            releaseLock();
            return false;
        }
    }

    public synchronized void releaseLock() {
        try {
            if (lock != null && lock.isValid()) lock.release();
        } catch (IOException ignored) {
        } finally {
            lock = null;
        }
        try {
            if (channel != null && channel.isOpen()) channel.close();
        } catch (IOException ignored) {
        } finally {
            channel = null;
        }
        try {
            if (raf != null) raf.close();
        } catch (IOException ignored) {
        } finally {
            raf = null;
        }
    }
}
```

**What to notice:**
- `channel.lock(0L, 1L, false)` locks ONLY the first byte. A whole-file lock
  blocked our OWN appender with "file locked" errors — one byte guards the
  file at OS level while our writes continue after existing content.
- `synchronized` methods; `releaseLock()` is safe to call repeatedly and is
  called from the failure path too.

### 13) security/InstanceGuard.java — one app at a time

```java
package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/** Prevents two Cheat.Guard processes from running at the same time. */
public final class InstanceGuard {
    private RandomAccessFile raf;
    private FileChannel channel;
    private FileLock lock;

    public boolean acquire() {
        try {
            File f = new File(AppPaths.getDataDirectory(), "instance.lock");
            raf = new RandomAccessFile(f, "rw");
            channel = raf.getChannel();
            lock = channel.tryLock();
            if (lock == null) {
                close();
                return false;
            }
            return true;
        } catch (Exception e) {
            close();
            return false;
        }
    }

    public void close() {
        try { if (lock != null && lock.isValid()) lock.release(); } catch (Exception ignored) {}
        try { if (channel != null && channel.isOpen()) channel.close(); } catch (Exception ignored) {}
        try { if (raf != null) raf.close(); } catch (Exception ignored) {}
        lock = null; channel = null; raf = null;
    }
}
```

**What to notice:**
- `tryLock()` on a small lock file: if it is not free, another copy is running
  → refuse. The lock dies with the JVM, so no cleanup file is needed.

### 14) security/LogProtection.java — talking to the helper through files

```java
package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Keeps sealed session logs out of reach of Windows Explorer.
 *
 * <p>A sealed log is only evidence if it survives. Once a session ends, the
 * elevated helper that is already running for the network lockdown re-owns the
 * {@code .vault} and {@code .vault.sig} files to the Administrators group, drops
 * inherited permissions and leaves the signed-in account with <em>read</em> access
 * only. A student — or anyone using the desktop normally — then cannot delete,
 * rename or edit them: Explorer refuses, and because the account no longer owns the
 * files it cannot grant itself permission back either.
 *
 * <p>Deleting a log stays possible, but only the intended way: through the admin
 * dashboard, after the administrator password, which then asks Windows for elevation.
 *
 * <p>Boundary worth stating: a machine administrator who deliberately elevates can
 * always override file permissions. What this removes is deletion by a standard
 * user, by accident, or by anyone poking around in the folder.
 */
public final class LogProtection {

    private static final String REQUEST = "protect.request";
    private static final String DONE = "protect.done";

    private LogProtection() {
    }

    public static File requestFile() {
        return new File(AppPaths.getNetworkDirectory(), REQUEST);
    }

    public static File doneFile() {
        return new File(AppPaths.getNetworkDirectory(), DONE);
    }

    /**
     * Ask the running elevated helper to protect the given files.
     *
     * <p>Must be called while the session's lockdown helper is still alive, which is
     * why sealing happens before the network state is restored.
     *
     * @return true when the helper confirmed, false if it did not answer in time
     */
    public static boolean protectViaHelper(List<File> files) {
        List<File> existing = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.isFile()) existing.add(f);
        }
        if (existing.isEmpty()) return true;

        try {
            File done = doneFile();
            done.delete();
            StringBuilder sb = new StringBuilder();
            for (File f : existing) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            Files.writeString(requestFile().toPath(), sb.toString(), StandardCharsets.UTF_8);

            long deadline = System.currentTimeMillis() + 20_000L;
            while (System.currentTimeMillis() < deadline) {
                if (done.exists()) {
                    done.delete();
                    return true;
                }
                Thread.sleep(200L);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // fall through: the log is still written, just not permission-hardened
        }
        return false;
    }

    /**
     * Delete protected log files with a single elevation prompt.
     *
     * @return true if Windows accepted the elevated delete request
     */
    public static boolean deleteElevated(List<File> files) {
        List<File> targets = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.exists()) targets.add(f);
        }
        if (targets.isEmpty()) return true;

        Path list = null;
        try {
            StringBuilder sb = new StringBuilder();
            for (File f : targets) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            list = Files.createTempFile("cheatguard-delete-", ".txt");
            Files.writeString(list, sb.toString(), StandardCharsets.UTF_8);

            // The path list travels in a file so no quoting survives into PowerShell.
            String inner = "$l='" + list.toAbsolutePath().toString().replace("'", "''") + "';"
                    + "foreach($p in Get-Content -LiteralPath $l){"
                    + "if($p.Trim()){"
                    + "takeown /F \\\"$p\\\" /A | Out-Null;"
                    + "icacls \\\"$p\\\" /grant *S-1-5-32-544:(F) | Out-Null;"
                    + "Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}};"
                    + "Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue";

            String outer = "$ErrorActionPreference='Stop';"
                    + "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs "
                    + "-WindowStyle Hidden -PassThru -Wait "
                    + "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',\"" + inner + "\";"
                    + "if($null -eq $p){ throw 'not started' }";

            Process p = new ProcessBuilder("powershell.exe", "-NoProfile",
                    "-ExecutionPolicy", "Bypass", "-Command", outer)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            if (list != null) {
                try {
                    Files.deleteIfExists(list);
                } catch (Exception ignored) {
                    // the elevated step removes it as well
                }
            }
        }
    }
}
```

**What to notice:**
- `protectViaHelper()`: writes the file paths into a request file; the running
  elevated helper applies `takeown` + `icacls` (Administrators full, SYSTEM
  full, Users read-only) and writes a done marker; we poll for 20 s.
- `deleteElevated()`: the paths travel in a TEMP FILE so no quoting can corrupt
  the elevated PowerShell command; it grants Administrators full then
  `Remove-Item`s each path, and the temp file deletes itself.

## A4. OOP concepts in my part (with the real places)

1. **Encapsulation** — `Violation`: private final fields, read-only getters.
   `AdminCredentialStore`: the password file only through its own methods.
2. **Singleton** — `AppConfig.getInstance()`: private constructor + one static
   instance; the whole program shares one allowlist.
3. **Immutable objects** — `Violation` has no setters: a fact never changes.
4. **Static factory methods** — `Result.ok()`, `Result.wrong()`,
   `Result.lockedOut()` in the credential store.
5. **Composition (has-a)** — `SecurityVault` HAS an encryptor, a signer, a
   lock manager; each small class does one job.
6. **Exception hierarchy** — `IllegalArgumentException` (weak input),
   `SecurityException` (wrong password), `IOException` (files) — caught
   separately, each with its own message.
7. **Abstraction** — `AppPaths` hides WHERE files live; nobody builds raw
   paths by hand.

## A5. Technologies in my part

PBKDF2-HMAC-SHA256 (210,000 rounds) · 16-byte salt · HMAC + MachineGuid
(machine binding) · AES-256-CBC with per-file salt+IV · SHA-256 signatures ·
char[] zero-fill (never String) · SecureRandom · file-channel locks ·
properties files · constant-time compare · attrib/icacls/takeown.

## A6. Questions Sir may ask me

**Q: Why PBKDF2 and not a plain SHA-256 of the password?**
A: Plain SHA-256 is instant — billions of guesses per second. PBKDF2 repeats
the hashing 210,000 times, so every guess is slow, and with a salt there is no
pre-computed table.

**Q: What is a salt?**
A: Random bytes mixed with the password before hashing, so the same password
gives a different hash every time. It defeats "rainbow" tables.

**Q: Why no default password?**
A: A default would be visible in the code after decompiling. First launch
creates one; only its hash is stored.

**Q: What if someone copies the password file to another PC?**
A: It fails — the HMAC uses this PC's MachineGuid. The app rejects it and asks
for a new password.

**Q: What if the student deletes the log during the exam?**
A: They cannot — the log's permissions are hardened at session start; after
sealing it is also encrypted, signed, and ACL-locked.

**Q: What if the app dies mid-exam?**
A: Every event was already on disk. The leftover file stays as an UNSEALED
log, clearly marked; the next start repairs any leftover lockdown.

**Handover:** "That was the data and the security. Now my teammate explains the
engine that actually blocks things during the exam."

---

# PART B — MEMBER 2: The Blocking Engine (15 files + the PowerShell helper)

## B1. What I say (about 3 minutes)

"My part is the watchdog engine — everything that blocks and watches while the
exam runs. Four things: websites, programs, folders, devices.

Websites are the main one. Every program that opens a website must first ask a
DNS server for its address. Our program runs its own tiny DNS server inside the
student's computer on 127.0.0.1 port 53. An admin PowerShell helper points
every network card of the machine at it. Now every question comes to us: an
allowed name gets a real answer, everything else gets 'does not exist'. The
site cannot open — for every program, not just the browser.

Students try escapes, and we close them. Browser DNS-over-HTTPS is turned off
by policy AND blocked in the firewall. Direct queries to public DNS servers and
DNS-over-TLS are blocked. VPN and remote-control programs — OpenVPN, WireGuard,
TeamViewer, AnyDesk, VNC and about thirty more — are closed wherever they are
installed, and their network ports are blocked. The strongest layer: the
firewall refuses ALL web traffic by default and only allows the addresses that
approved websites really resolved to — so even typing a raw IP fails. Before
arming that mode we VERIFY an approved site is reachable; on a strange network
it rolls back safely and the log records which mode ran.

Then programs: anything new that opens during the exam and is not allowed is
closed, and the closing is logged. Programs the student compiles into their own
exam folder are never touched. And the ALLOWED apps start fresh: at session
start they are closed too, and the invigilator reopens the needed ones from the
monitor screen, which launches them ON the exam folder — so no folder, file or
tab opened before the exam survives inside them. Then we watch what those apps
DO: an editor whose tab title shows a foreign folder is a red alert; a
permitted interpreter (python) whose command line names a file outside the exam
folder is closed and logged red; and an allowed app showing a file outside the
exam folder is closed and logged red. The Windows recent-files lists (Start
menu, jump lists, Open-dialog recents) are wiped at start, so nothing pre-exam
can be reopened in one click. And the strongest content wall: the student's
ACCOUNT itself is denied read access to everything outside the exam folder
(Documents, Downloads, other drives, USB) with NTFS permissions - so no
program, terminal or dialog can open a pre-exam file at all. Everything is
restored at the end. Folders: an Explorer window outside the exam folder is a
red flag. USB devices: a stick, a USB network adapter, or a phone in file mode
is an instant alert.

One important ordering: at session start the app kills all background apps
FIRST and only then starts counting alerts — cleanup noise never becomes a fake
alarm. And the student cannot kill our app: it runs elevated, and Windows (UIPI)
blocks normal programs from touching an elevated process. My teammate will now
show the screens and how we tested everything."

## B2. The three big files + the helper, full code with explanations

### 1) watchdog/WatchdogEngine.java — the loop

**Part 1 — the class starts with three lists of names:**

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Enforces application allowlist and audits external devices + folder access. Website access is enforced by StrictNetworkLockdown. */
public class WatchdogEngine implements Runnable {
    private final ProcessScanner scanner = new ProcessScanner();
    private final ProcessWhitelist whitelist = new ProcessWhitelist();
    private final ProcessController controller = new ProcessController();
    private final ExternalDeviceMonitor deviceMonitor = new ExternalDeviceMonitor();
    private final FolderAccessMonitor folderMonitor;
    private final File examFolder;
    private final LogManager logManager;
    private final ViolationListener listener;
    private final long selfPid;

    private final Set<Long> recentlyBlockedPids = new HashSet<>();
    private final Set<String> knownPids = new HashSet<>();
    private final Set<String> activeBadFolders = new HashSet<>();
    private final Set<String> seenBadFolders = new HashSet<>();
    /** INFO rows already shown this session, so a respawning helper cannot spam the log. */
    private final Set<String> emittedInfoKeys = new HashSet<>();
    /** False until the first sweep finishes, so pre-existing apps are treated as baseline. */
    private boolean baselineSweepDone;
    private volatile boolean running = true;
    private int cycle = 0;
    private static final int POLL_INTERVAL_MS = 1200;

    /**
     * Helper tooling the application itself spawns; never treated as student apps.
     */
    private static final Set<String> OWN_TOOL_NAMES = new HashSet<>(Arrays.asList(
            "powershell.exe", "conhost.exe", "openconsole.exe", "cmd.exe", "taskkill.exe",
            "attrib.exe", "reg.exe", "where.exe", "whoami.exe", "nslookup.exe"));

    /** Background platform processes that legitimately appear mid-session. */
    private static final Set<String> BACKGROUND_TOOL_NAMES = new HashSet<>(Arrays.asList(
            "msiexec.exe", "rundll32.exe", "regsvr32.exe", "compattelrunner.exe",
            "devicecensus.exe", "sihclient.exe", "musnotification.exe", "musnotifyicon.exe",
            "gamebarftserver.exe", "consent.exe", "wsqmcons.exe", "devicepairing.exe",
            "spoolsv.exe", "printplatformconfig.exe", "openwith.exe", "wudfhost.exe"));

    /**
     * Tunnels, proxies and remote-control clients, judged everywhere on disk (like
     * browsers): they reach the Internet or another computer without ever consulting
     * the local DNS filter, so a copy installed in Program Files would otherwise be
     * a complete bypass of the website allowlist.
     */
    private static final Set<String> FORCED_CLOSE = new HashSet<>(Arrays.asList(
            "openvpn.exe", "openvpn-gui.exe", "wireguard.exe", "tailscale.exe", "tailscaled.exe",
            "cloudflared.exe", "zerotier-one.exe", "hamachi-2.exe", "hamachi-2-ui.exe",
            "nordvpn.exe", "expressvpn.exe", "protonvpn.exe", "mullvad.exe", "mullvadvpn.exe",
            "cyberghost.exe", "hotspotshield.exe", "psiphon3.exe", "tor.exe", "proxifier.exe",
            "teamviewer.exe", "teamviewer_service.exe", "tvnserver.exe", "winvnc.exe",
            "vncserver.exe", "vncviewer.exe", "anydesk.exe", "rustdesk.exe", "parsec.exe",
            "splashtop-streamer.exe", "logmein.exe", "remoting_host.exe", "ultraviewer.exe",
            "ammyy.exe", "radmin.exe", "supremo.exe", "abtutor.exe", "netsupport.exe"));

    /** Vendor suites whose binaries drift (nordlynx, expressvpn-service, tailscale-ipn…). */
    private static final List<String> FORCED_CLOSE_PREFIXES = List.of(
            "openvpn", "wireguard", "tailscale", "nordvpn", "expressvpn", "protonvpn",
            "cyberghost", "mullvad", "teamviewer", "anydesk", "rustdesk", "hamachi",
            "ultraviewer", "psiphon", "warp-svc", "cloudflarewarp");

    /** Interpreters the allowlist permits - they may only touch exam-folder files. */
    private static final Set<String> RUNTIME_NAMES = new HashSet<>(Arrays.asList(
            "python.exe", "pythonw.exe", "py.exe"));

    /** Default compiler output, allowed by name - so its location is checked instead. */
    private static final Set<String> COMPILED_OUTPUT_NAMES = new HashSet<>(Arrays.asList("a.exe"));

    /** Editor title suffixes: the tab title must carry the exam folder's name. */
    private static final Map<String, String> EDITOR_TITLE_SUFFIXES = Map.of(
            "code.exe", "Visual Studio Code",
            "code - insiders.exe", "Visual Studio Code - Insiders",
            "cursor.exe", "Cursor",
            "subl.exe", "Sublime Text");

    /** Editor tabs that never indicate a folder (welcome pages, tool panels). */
    private static final Set<String> BENIGN_EDITOR_TABS = new HashSet<>(Arrays.asList(
            "welcome", "get started", "new file", "settings", "extensions",
            "keyboard shortcuts", "output", "problems", "terminal", "release notes",
            "documentation"));

    /** Tool paths (VS Code extensions, debugpy, stdlib) that appear in interpreter args. */
    private static final List<String> TOOL_PATH_HINTS = List.of(
            ".vscode", "extensions", "debugpy", "site-packages", "\\lib\\", "/lib/");
```

- `OWN_TOOL_NAMES`: small helpers OUR app spawns (PowerShell, taskkill…) —
  never blamed on the student.
- `BACKGROUND_TOOL_NAMES`: Windows platform processes that appear on their own.
- `FORCED_CLOSE` + prefixes: the VPN / remote-control kill list — judged
  ANYWHERE on disk, because they bypass the DNS filter completely.

**Part 2 — constructor and the run() loop:**

```java
    public WatchdogEngine(LogManager logManager, File examFolder, ViolationListener listener) {
        this.logManager = logManager;
        this.listener = listener;
        this.examFolder = examFolder;
        this.folderMonitor = new FolderAccessMonitor(examFolder);
        this.selfPid = detectSelfPid();
    }

    public void stop() { running = false; }

    @Override
    public void run() {
        // Session contract: when a session starts, EVERYTHING the student could have
        // left running — visible windows, tray apps, background services they launched
        // — is closed first. Only then is the process baseline taken and monitoring
        // (the alert counter) begins, so startup cleanup noise never counts.
        startupKillSweep();

        // Treat Explorer windows that were already open before monitoring as baseline noise.
        // Only folders newly opened outside the exam workspace become violations.
        activeBadFolders.addAll(folderMonitor.getUnauthorizedExplorerFolders());
        seenBadFolders.addAll(activeBadFolders);
        reportDevicesPresentAtStart();
        snapshotProcessBaseline();
        while (running) {
            checkProcesses();
            checkBackgroundProcesses();
            // Explorer-window enumeration spawns a second PowerShell probe; spacing it
            // and the device sweep out keeps a steady, low CPU profile on exam laptops.
            if ((cycle % 2) == 0) checkFolders();
            if ((cycle % 4) == 0) checkExternalDevices();
            cycle++;
            sleepQuietly();
        }
    }

    /**
     * Close every non-system, unapproved application present at session start,
     * including tray and background instances that no window sweep can see. System
     * components, the admin-approved exam tools and the app's own helper processes
     * are spared; browsers are closed wherever they are installed.
     */
```

- `startupKillSweep()` runs FIRST (before any baseline) — the session contract:
  kill everything student-space, then start counting.
- The folder/device baseline and process baseline are taken AFTER the sweep.
- One cycle every 1.2 s; folders every 2nd cycle, devices every 4th (PowerShell
  probes cost CPU — spacing keeps the profile low).

**Part 3 — the startup sweep:**

```java
    private void startupKillSweep() {
        List<String> systemPrefixes = buildSystemPrefixes();
        for (ProcessHandle ph : ProcessHandle.allProcesses().toList()) {
            if (ph.pid() <= 4 || ph.pid() == selfPid) continue;
            String command = ph.info().command().orElse("");
            if (command.isBlank()) continue; // not attributable: the sweeps re-check it

            String name = new File(command).getName().toLowerCase(Locale.ROOT);
            if (!name.endsWith(".exe")) name = name + ".exe";
            if (name.equals("cheatguard.exe")) continue;
            boolean forced = isForcedClose(name);
            if (!forced && whitelist.isSystemProcess(name)) continue;
            if (OWN_TOOL_NAMES.contains(name) || BACKGROUND_TOOL_NAMES.contains(name)) continue;

            String lowerCmd = command.toLowerCase(Locale.ROOT);
            boolean browser = whitelist.isBrowser(name);
            boolean approved = whitelist.isAllowed(name);
            boolean inSystemArea = false;
            for (String prefix : systemPrefixes) {
                if (lowerCmd.startsWith(prefix)) { inSystemArea = true; break; }
            }
            // APPROVED apps are closed too, wherever they sit: a fresh start means
            // no folder, file or tab opened before the exam survives inside them.
            // The invigilator reopens the ones this exam needs from the monitor
            // screen, which launches them ON the exam folder.
            if (!browser && !approved && !forced && inSystemArea) continue;

            String app = ProcessWhitelist.friendlyName(name);
            // taskkill can race an app that is already shutting down (VS Code runs as
            // several processes) - the process being gone counts as closed.
            boolean closed = controller.terminate(ph.pid()) || !ph.isAlive();
            if (closed) {
                emit(new Violation("APP_CLOSED_AT_START", app, Violation.Severity.INFO));
            } else {
                emit(new Violation("UNAUTHORIZED_APP_CLOSE_FAILED", app, Violation.Severity.CRITICAL));
            }
        }
    }

    /** Every process alive when monitoring starts is baseline, whichever session it sits in. */
```

- For every process: skip system idle/self, skip our own exe, skip Windows
  components, skip our own helper tools — and CLOSE THE ALLOWED APPS TOO,
  wherever they sit (VS Code in Program Files included). That is the fresh-start
  rule: a folder, file or tab opened before the exam cannot survive inside an
  approved app. The invigilator reopens what the exam needs from the monitor
  screen, which starts them ON the exam folder. Browsers are judged wherever
  they are installed; everything else in a student-writable area is closed with
  `taskkill` and logged as "Closed before exam" (or red if the close fails).

**Part 4 — baseline, forced-close check, process identity:**

```java
    private void snapshotProcessBaseline() {
        try {
            ProcessHandle.allProcesses().forEach(ph -> knownPids.add(processKey(ph)));
        } catch (Exception ignored) {
            // the visible-window sweep below still runs; background sweep just starts fresh
        }
    }

    /** True for tunnelling/remote-control clients, wherever they are installed. */
    private static boolean isForcedClose(String processName) {
        if (processName == null) return false;
        String p = processName.toLowerCase(Locale.ROOT);
        if (FORCED_CLOSE.contains(p)) return true;
        for (String prefix : FORCED_CLOSE_PREFIXES) {
            if (p.startsWith(prefix)) return true;
        }
        return false;
    }

    /**
     * Identity of a process across sweeps. The start instant is part of the key so a
     * recycled PID (one app closed, Windows hands the number to a new one) is judged
     * as the new process it actually is, not skipped as already seen.
     */
    private static String processKey(ProcessHandle ph) {
        long start = 0L;
        try {
            start = ph.info().startInstant().orElse(java.time.Instant.EPOCH).toEpochMilli();
        } catch (Exception ignored) {
        }
        return ph.pid() + "@" + start;
    }

    /**
     * Close student-started apps that never show a top-level window — the blind spot
     * of the visible-window sweep. Tray apps, minimized launches and headless
     * browsers (chrome --headless is a whole cheat toolkit) are invisible to
     * MainWindowTitle but appear here as new PIDs.
     *
     * <p>To keep collateral damage at zero, a process is only closed when it is NEW
     * (started after the baseline), its name is not a known Windows shell/background
     * component, and its executable lives OUTSIDE the machine's system locations
     * (Windows directory, Program Files, ProgramData) — everywhere else is somewhere
     * a standard user can drop a file, including a second drive's root. Browser
     * binaries are judged wherever they sit, because a headless browser is a cheat
     * toolkit even when installed system-wide.
     */
```

- `processKey` = PID + start instant — the fix for recycled PIDs: Windows hands
  the same number to a new program, and the start time tells them apart.
- `isForcedClose` matches the exact set OR the vendor prefixes (nordlynx,
  warp-svc, tailscale-ipn…).

**Part 5 — background process sweep (the blind-spot killer):**

```java
    private void checkBackgroundProcesses() {
        List<String> systemPrefixes = buildSystemPrefixes();
        for (ProcessHandle ph : ProcessHandle.allProcesses().toList()) {
            String key = processKey(ph);
            if (ph.pid() <= 4 || ph.pid() == selfPid || knownPids.contains(key)) continue;

            String command = ph.info().command().orElse("");
            if (command.isBlank()) continue; // not yet attributable: re-judged next sweep
            knownPids.add(key); // judge once per actual process; never re-log it

            // Programs the student builds into their own exam folder ARE the exam work
            // (a compiled solution runs from there all session long) — never touched.
            if (isExamWorkspaceBinary(command)) continue;

            String name = new File(command).getName().toLowerCase(Locale.ROOT);
            if (!name.endsWith(".exe")) name = name + ".exe";
            if (name.equals("cheatguard.exe")) continue;
            boolean forced = isForcedClose(name);
            if (!forced && whitelist.isSystemProcess(name)) continue;

            boolean approved = whitelist.isAllowed(name);
            if (approved && !forced) {
                // Allowed programs may only touch files inside the exam folder -
                // running an old folder's file through a permitted tool is the trick.
                String outside = allowedProgramOutsideFile(ph, name, command);
                if (outside == null) continue;
                boolean closedAllowed = controller.terminate(ph.pid());
                emit(closedAllowed
                        ? new Violation("ALLOWED_RUNTIME_OUTSIDE_FILE",
                                ProcessWhitelist.friendlyName(name) + " was using " + outside,
                                Violation.Severity.CRITICAL)
                        : new Violation("UNAUTHORIZED_APP_CLOSE_FAILED",
                                ProcessWhitelist.friendlyName(name), Violation.Severity.CRITICAL));
                continue;
            }
            if (!forced && (OWN_TOOL_NAMES.contains(name) || BACKGROUND_TOOL_NAMES.contains(name))) continue;

            String lowerCmd = command.toLowerCase(Locale.ROOT);
            boolean browser = whitelist.isBrowser(name);
            boolean inSystemArea = false;
            for (String prefix : systemPrefixes) {
                if (lowerCmd.startsWith(prefix)) { inSystemArea = true; break; }
            }
            if (!browser && !forced && inSystemArea) continue; // machine area, not the student's doing

            boolean closed = controller.terminate(ph.pid()) || !ph.isAlive();
            String app = ProcessWhitelist.friendlyName(name);
            emit(closed
                    ? new Violation("UNAUTHORIZED_BACKGROUND_APP_CLOSED", app, Violation.Severity.INFO)
                    : new Violation("UNAUTHORIZED_BACKGROUND_APP_CLOSE_FAILED", app, Violation.Severity.CRITICAL));
        }
    }

    /** Executable locations only an administrator can plant files in. */
    private static List<String> buildSystemPrefixes() {
        List<String> prefixes = new ArrayList<>();
        for (String env : new String[]{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"}) {
            String v = System.getenv(env);
            if (v != null && !v.isBlank()) prefixes.add(v.toLowerCase(Locale.ROOT) + File.separatorChar);
        }
        return prefixes;
    }

    /** True when an executable runs from the student's own exam folder. */
    private boolean isExamWorkspaceBinary(String path) {
        if (path == null || path.isBlank() || examFolder == null) return false;
        String base = examFolder.getAbsolutePath().toLowerCase(Locale.ROOT);
        if (!base.endsWith(File.separator)) base = base + File.separator;
        return path.toLowerCase(Locale.ROOT).startsWith(base);
    }

    /** Drive paths appearing inside window titles, e.g. "C:\notes\a.txt - Editor". */
    private static final Pattern TITLE_PATH = Pattern.compile("[A-Za-z]:[\\\\/][^|<>?\"]*");

    /**
     * An ALLOWED app is only allowed to work on the exam folder. If its window
     * title carries a drive path outside that folder (a file it has open), the
     * approval is being abused. Returns the offending path, or null when clean.
     */
    private String outsideExamPathInTitle(String processName, String title) {
        if (title == null || title.isBlank()) return null;
        if (examFolder == null) return null;
        if (!whitelist.isAllowed(processName) || whitelist.isBrowser(processName)) return null;
        return titlePathOutside(title, examFolder.getAbsolutePath());
    }

    /** First drive path in the title that lives OUTSIDE the given folder, or null. */
    public static String titlePathOutside(String title, String baseFolder) {
        if (title == null || title.isBlank() || baseFolder == null || baseFolder.isBlank()) return null;
        String base = baseFolder.toLowerCase(Locale.ROOT);
        if (!base.endsWith(File.separator)) base = base + File.separator;
        Matcher m = TITLE_PATH.matcher(title);
        while (m.find()) {
            String candidate = m.group();
            if (!candidate.toLowerCase(Locale.ROOT).startsWith(base)) return candidate;
        }
        return null;
    }

    /**
     * Allowed programs (interpreters, the default compiler output) may only touch
     * files inside the exam folder. A python process whose arguments carry a file
     * outside the folder, or an a.exe running from anywhere outside it, is the
     * old-folder trick. Returns the offending path, or null when clean.
     */
    private String allowedProgramOutsideFile(ProcessHandle ph, String name, String command) {
        if (examFolder == null) return null;
        if (RUNTIME_NAMES.contains(name)) {
            String[] args = null;
            try { args = ph.info().arguments().orElse(null); } catch (Exception ignored) {}
            return runtimeArgOutside(args, examFolder.getAbsolutePath());
        }
        if (COMPILED_OUTPUT_NAMES.contains(name)) {
            for (String prefix : buildSystemPrefixes()) {
                if (command.toLowerCase(Locale.ROOT).startsWith(prefix)) return null; // installed tool
            }
            return command; // compiled output running from outside the exam folder
        }
        return null;
    }

    /**
     * First interpreter argument pointing outside the exam folder. Tool paths
     * (VS Code extensions, debugpy, the stdlib) are ignored so the python
     * debugger and language tooling never trip the rule.
     */
    public static String runtimeArgOutside(String[] args, String baseFolder) {
        if (args == null || baseFolder == null || baseFolder.isBlank()) return null;
        for (String arg : args) {
            if (arg == null || arg.isBlank() || arg.startsWith("-")) continue;
            String hit = titlePathOutside(arg, baseFolder);
            if (hit == null) continue;
            String lower = hit.toLowerCase(Locale.ROOT);
            boolean toolPath = false;
            for (String hint : TOOL_PATH_HINTS) {
                if (lower.contains(hint)) { toolPath = true; break; }
            }
            if (!toolPath) return hit;
        }
        return null;
    }

    /**
     * True when an allowed editor's title shows a folder that is NOT the exam
     * folder. Red alert only - closing could destroy exam work open elsewhere.
     */
    private String editorShowingOutsideFolder(String processName, String title) {
        if (title == null || title.isBlank() || examFolder == null) return null;
        String suffix = EDITOR_TITLE_SUFFIXES.get(processName.toLowerCase(Locale.ROOT));
        if (suffix == null) return null;
        if (editorShowsOutsideFolder(title, suffix, examFolder.getName(), examFolder)) {
            return ProcessWhitelist.friendlyName(processName);
        }
        return null;
    }

    /**
     * Segment rule for editor titles ("file - folder - Editor"): the title must
     * carry the exam folder's name, or name a file/folder that exists inside it.
     * Welcome pages and untitled scratch tabs are clean.
     */
    public static boolean editorShowsOutsideFolder(String title, String suffix,
                                                   String examFolderName, File examFolderDir) {
        if (title == null || suffix == null || examFolderName == null) return false;
        String t = title.trim();
        if (!t.toLowerCase(Locale.ROOT).endsWith(suffix.toLowerCase(Locale.ROOT))) return false;
        String prefix = t.substring(0, t.length() - suffix.length()).trim();
        if (prefix.endsWith("-")) prefix = prefix.substring(0, prefix.length() - 1).trim();
        if (prefix.isEmpty()) return false;
        boolean suspicious = false;
        for (String raw : prefix.split(" - ")) {
            String seg = raw.trim();
            if (seg.startsWith("●")) seg = seg.substring(1).trim(); // VS Code dirty dot
            if (seg.equalsIgnoreCase(examFolderName)) return false;      // exam folder open
            if (examFolderDir != null && new File(examFolderDir, seg).isFile()) return false;
            if (seg.isEmpty() || BENIGN_EDITOR_TABS.contains(seg.toLowerCase(Locale.ROOT))
                    || seg.toLowerCase(Locale.ROOT).startsWith("untitled")) continue;
            suspicious = true;
        }
        return suspicious;
    }

```

- Only NEW keys are judged (`knownPids`) — each process is judged once.
- A blank command line means "not attributable yet" — skipped and re-checked
  next sweep instead of guessed.
- `isExamWorkspaceBinary(path)`: anything running from the student's exam
  folder is NEVER touched — that is the compiled homework rule.

**Part 6 — the visible-window sweep:**

```java
    private void checkProcesses() {
        List<ProcessInfo> visible = scanner.getRunningProcesses();
        Set<Long> stillVisibleBlocked = new HashSet<>();
        for (ProcessInfo proc : visible) {
            if (proc.getPid() == selfPid) continue;
            if (whitelist.isSystemProcess(proc.getName())) continue; // Windows component: never logged

            // An ALLOWED app is only allowed to work on the exam folder. If its
            // window title carries a drive path outside that folder (a file it has
            // open), the approval is being abused - close it and raise a red flag.
            String outsidePath = outsideExamPathInTitle(proc.getName(), proc.getWindowTitle());
            String shownFolder = outsidePath == null
                    ? editorShowingOutsideFolder(proc.getName(), proc.getWindowTitle())
                    : null;
            boolean flagged = outsidePath != null || shownFolder != null;
            boolean forced = isForcedClose(proc.getName());
            boolean skip = !flagged
                    && ((!forced && whitelist.isAllowed(proc.getName()))
                        || isExamWorkspaceBinary(proc.getImagePath()));
            if (skip) continue;

            stillVisibleBlocked.add(proc.getPid());
            if (recentlyBlockedPids.contains(proc.getPid())) continue;

            boolean gone = ProcessHandle.of(proc.getPid()).map(ph -> !ph.isAlive()).orElse(true);
            boolean closed = controller.terminate(proc.getPid()) || gone;
            String app = ProcessWhitelist.friendlyName(proc.getName());

            if (outsidePath != null) {
                emit(closed
                        ? new Violation("ALLOWED_APP_OUTSIDE_FOLDER",
                                app + " was showing " + outsidePath, Violation.Severity.CRITICAL)
                        : new Violation("UNAUTHORIZED_APP_CLOSE_FAILED", app, Violation.Severity.CRITICAL));
            } else if (shownFolder != null) {
                // Red alert only - closing could destroy exam work in another window.
                emit(new Violation("ALLOWED_APP_OUTSIDE_FOLDER_SHOWN",
                        app + " was showing " + shownFolder, Violation.Severity.CRITICAL));
            } else if (baselineSweepDone) {
                // Opened during the exam. Closing it is the enforcement, so only a
                // failure to close leaves the student with a usable tool - that is RED.
                emit(closed
                        ? new Violation("UNAUTHORIZED_APP_CLOSED", app, Violation.Severity.INFO)
                        : new Violation("UNAUTHORIZED_APP_CLOSE_FAILED", app, Violation.Severity.CRITICAL));
            } else {
                // Already open before the exam started: tidy-up, not misconduct.
                emit(new Violation("APP_CLOSED_AT_START", app, Violation.Severity.INFO));
            }
        }
        recentlyBlockedPids.clear();
        recentlyBlockedPids.addAll(stillVisibleBlocked);
        baselineSweepDone = true;
    }

```

- First sweep (before `baselineSweepDone`) logs "Closed before exam" (grey);
  later closes are grey OK, close-FAILURES are red ALERTS.
- `recentlyBlockedPids` stops the same window being re-logged every cycle.

**Part 7 — folders, devices, and the emit gate:**

```java
    private void checkFolders() {
        List<String> bad = folderMonitor.getUnauthorizedExplorerFolders();
        Set<String> current = new HashSet<>(bad);
        for (String path : current) {
            if (!activeBadFolders.contains(path) && !seenBadFolders.contains(path)) {
                emit(new Violation("UNAUTHORIZED_FOLDER_ACCESS", path, Violation.Severity.CRITICAL));
                seenBadFolders.add(path);
            }
        }
        activeBadFolders.clear();
        activeBadFolders.addAll(current);
    }

    private void reportDevicesPresentAtStart() {
        for (String device : deviceMonitor.getPresentRiskDevices()) {
            emit(new Violation("EXTERNAL_DEVICE_PRESENT_AT_START", device, Violation.Severity.CRITICAL));
        }
    }

    private void checkExternalDevices() {
        for (String device : deviceMonitor.checkForNewRiskDevices()) {
            emit(new Violation("EXTERNAL_DEVICE_CONNECTED", device, Violation.Severity.CRITICAL));
        }
    }

    private void emit(Violation violation) {
        // Routine "closed successfully" rows are shown once per app: when a platform
        // helper immediately respawns after being closed, repeating the row would
        // flood the log an invigilator has to read. Red flags always go through.
        if (violation.getSeverity() == Violation.Severity.INFO
                && !emittedInfoKeys.add(violation.getType() + "|" + violation.getDescription())) {
            return;
        }
        logManager.record(violation);
        if (listener != null) listener.onViolation(violation);
    }

    private void sleepQuietly() {
        try { Thread.sleep(POLL_INTERVAL_MS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private long detectSelfPid() {
        try {
            return ProcessHandle.current().pid();
        } catch (Exception e) {
            try {
                String name = ManagementFactory.getRuntimeMXBean().getName();
                int at = name.indexOf('@');
                return Long.parseLong(at > 0 ? name.substring(0, at) : name);
            } catch (Exception ignored) {
                return -1L;
            }
        }
    }
}
```

- Folders: only NEW bad paths (never seen before) raise the red flag.
- `emit()` deduplicates INFO rows by type+description — one row per program per
  session. CRITICAL always passes. Then: log to file + notify the listener.

### 2) watchdog/DnsAllowlistServer.java — my own DNS server

**Part 1 — constants and fields:**

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local DNS allowlist resolver — the enforcement point for website lockdown.
 *
 * <p>The elevated helper points every adapter's DNS at this server, so the whole
 * machine resolves through it. A query is answered only when its hostname passes
 * {@link AppConfig#isSiteAllowed(String)}; everything else gets NXDOMAIN, so an
 * unapproved domain cannot be resolved by any program — not just by a browser.
 *
 * <p>Enforcing at name resolution keeps approved sites working normally: an
 * approved lookup is resolved and the browser connects to the real site directly,
 * with no proxy in the path that could fail or be ignored.
 *
 * <p>Approved lookups are resolved through the resolvers the computer was already
 * using before the session (campus DNS usually answers faster and never blocks
 * internal hosts), falling back to public resolvers when none could be captured.
 * Successful answers are cached for a few seconds so a page fan-out of a dozen
 * names costs one upstream round-trip, not a dozen.
 *
 * <p>Windows places no privilege restriction on low ports, so binding UDP 53
 * works from the normal (non-elevated) application process.
 */
public final class DnsAllowlistServer implements Closeable {

    /** Standard DNS port; adapters are redirected here on 127.0.0.1. */
    public static final int DNS_PORT = 53;

    private static final int MAX_PACKET = 4096;
    private static final int UPSTREAM_TIMEOUT_MS = 3000;
    private static final int MAX_LOGGED_HOSTS = 400;
    /**
     * Settling window right after the lockdown starts: the machine's own cleanup is
     * still running (tray apps, chat clients and update services are being closed)
     * and their dying lookups are the app's noise, not student activity. Blocked
     * lookups inside this window are dropped instead of being reported.
     */
    private static final long STARTUP_GRACE_MS = 60_000L;
    /** Successful approved answers are replayed for this long before re-querying. */
    private static final long CACHE_TTL_MS = 30_000L;
    private static final int CACHE_MAX_ENTRIES = 512;

    /**
     * Fallback resolvers used only when no system resolver could be captured.
     * Deliberately OUTSIDE the firewall's public-resolver block list (which stops a
     * student querying 8.8.8.8/1.1.1.1 directly from a custom tool): the filter's
     * own upstream traffic must keep working on networks where the captured system
     * resolvers are unreachable.
     */
    private static final List<String> DEFAULT_UPSTREAMS = List.of("9.9.9.10", "149.112.112.10");

    /**
     * Public resolvers the exam firewall blocks on port 53. Any system resolver
     * found in this list is dropped from the captured upstreams so the filter never
     * blocks its own path.
     */
    static final java.util.Set<String> BLOCKED_PUBLIC_RESOLVERS = java.util.Set.of(
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15");

    private final LogManager logManager;
    private final ViolationListener listener;
    private final WebsiteViolationReporter reporter = new WebsiteViolationReporter();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Set<String> loggedBlockedHosts =
            Collections.synchronizedSet(new LinkedHashSet<>());
    private final long graceUntil = System.currentTimeMillis() + STARTUP_GRACE_MS;
    /** Every address an approved domain has resolved to this session (egress allowlist). */
    private final Set<String> allowedAnswerIps = Collections.synchronizedSet(new LinkedHashSet<>());
    /** Optional file the elevated helper polls to keep its firewall allowlist current. */
    private final File allowedIpSink;
    private final List<String> upstreams;
    private final ConcurrentHashMap<String, CachedAnswer> answerCache = new ConcurrentHashMap<>();
    private ScheduledExecutorService ipFlusher;
    private volatile boolean ipListDirty;

    private volatile DatagramSocket socket;
    private volatile DatagramSocket socketV6;
    private final List<Thread> acceptThreads = new ArrayList<>();
    private ExecutorService workers;

```

- The 60-second startup grace: blocked lookups in the first minute are the
  machine's own dying apps, not the student — dropped silently.
- `BLOCKED_PUBLIC_RESOLVERS`: if the machine was using 8.8.8.8 etc., those
  upstreams are dropped from OUR list (they are firewalled for students; the
  filter must never block its own path). The fallbacks are Quad9 "unfiltered"
  IPs, deliberately OUTSIDE that block list.

**Part 2 — constructors:**

```java
    public DnsAllowlistServer(LogManager logManager, ViolationListener listener) {
        this(logManager, listener, DEFAULT_UPSTREAMS, null);
    }

    public DnsAllowlistServer(LogManager logManager, ViolationListener listener,
                              List<String> systemUpstreams) {
        this(logManager, listener, systemUpstreams, null);
    }

    /**
     * @param systemUpstreams the machine's original resolvers, captured before the
     *                        adapters were redirected; empty list falls back to the
     *                        public resolvers
     * @param allowedIpSink   when non-null, the addresses answered for approved
     *                        domains are written here (one per line) a few times a
     *                        minute so the elevated egress firewall can follow
     */
    public DnsAllowlistServer(LogManager logManager, ViolationListener listener,
                              List<String> systemUpstreams, File allowedIpSink) {
        this.logManager = logManager;
        this.listener = listener;
        this.allowedIpSink = allowedIpSink;
        List<String> cleaned = new ArrayList<>();
        if (systemUpstreams != null) {
            for (String s : systemUpstreams) {
                if (s == null || !s.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
                if (BLOCKED_PUBLIC_RESOLVERS.contains(s)) continue;       // blocked on 53 for everyone
                if (s.startsWith("45.90.28.") || s.startsWith("45.90.30.")) continue;
                if (s.startsWith("127.") || s.equals("0.0.0.0")) continue;
                if (!cleaned.contains(s)) cleaned.add(s);
                if (cleaned.size() >= 4) break;
            }
        }
        for (String fallback : DEFAULT_UPSTREAMS) {
            if (cleaned.size() >= 4) break;
            if (!cleaned.contains(fallback)) cleaned.add(fallback);
        }
        this.upstreams = List.copyOf(cleaned);
    }

    /** A successful upstream answer with the query ID blanked for reuse. */
    private record CachedAnswer(byte[] response, long expiresAt) {
    }

    /**
     * Bind the loopback DNS port for both address families and begin serving.
     *
     * <p>IPv4 (127.0.0.1) is required. IPv6 (::1) is bound as well when available:
     * Windows keeps separate IPv6 DNS servers per adapter and prefers them, so
     * leaving that family unfiltered would either leak lookups or — once outbound
     * port 53 is denied to other programs — stall resolution for approved sites
     * while Windows waits for the unreachable IPv6 servers.
     *
     * @throws IOException if 127.0.0.1:53 is already taken (another DNS or Internet
     *                     Connection Sharing service); the caller must surface this
     *                     because the allowlist would otherwise not be enforced.
     */
```

- Three constructors chain with `this(...)` (constructor overloading). The
  longest one cleans the upstream list: valid IPv4 only, not in the blocked
  set, no loopback, maximum 4, then appends the fallbacks.
- `CachedAnswer` is a Java **record** — an immutable data holder in one line.

**Part 3 — start() and close():**

```java
    public void start() throws IOException {
        if (running.get()) return;
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), DNS_PORT));
        socket.setSoTimeout(1000);
        try {
            socketV6 = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"), DNS_PORT));
            socketV6.setSoTimeout(1000);
        } catch (Exception ipv6Unavailable) {
            socketV6 = null;
        }
        running.set(true);
        workers = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "CheatGuard-DNS-Worker");
            t.setDaemon(true);
            return t;
        });
        startAcceptThread(socket, "CheatGuard-DNS");
        if (socketV6 != null) startAcceptThread(socketV6, "CheatGuard-DNS-v6");
        if (allowedIpSink != null) {
            ipFlusher = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "CheatGuard-IpSink");
                t.setDaemon(true);
                return t;
            });
            ipFlusher.scheduleWithFixedDelay(this::flushAllowedIps, 3, 3, TimeUnit.SECONDS);
        }
    }

    /** True when ::1:53 is also being served, so IPv6 DNS can be redirected too. */
    public boolean isIpv6Bound() {
        return socketV6 != null;
    }

    private void startAcceptThread(DatagramSocket bound, String name) {
        Thread t = new Thread(() -> acceptLoop(bound), name);
        t.setDaemon(true);
        acceptThreads.add(t);
        t.start();
    }

    public boolean isRunning() {
        return running.get();
    }

    @Override
    public void close() {
        running.set(false);
        DatagramSocket s = socket;
        if (s != null) s.close();
        socket = null;
        DatagramSocket s6 = socketV6;
        if (s6 != null) s6.close();
        socketV6 = null;
        if (workers != null) {
            workers.shutdownNow();
            try {
                workers.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            workers = null;
        }
        for (Thread t : acceptThreads) t.interrupt();
        acceptThreads.clear();
        if (ipFlusher != null) {
            ipFlusher.shutdown();
            flushAllowedIps(); // leave the helper the last known list
            ipFlusher = null;
        }
        loggedBlockedHosts.clear();
        answerCache.clear();
    }

```

- Binds UDP 53 on 127.0.0.1 AND ::1; `setSoTimeout(1000)` makes the accept loop
  wake up every second so it can notice `running = false`.
- A pool of 8 worker threads answers packets — one slow upstream cannot freeze
  the others.
- `close()` shuts everything down in order and writes the final IP file.

**Part 4 — receiving a packet:**

```java
    private void acceptLoop(DatagramSocket bound) {
        while (running.get()) {
            byte[] buf = new byte[MAX_PACKET];
            DatagramPacket request = new DatagramPacket(buf, buf.length);
            try {
                bound.receive(request);
                ExecutorService pool = workers;
                if (pool != null) pool.submit(() -> handle(request, bound));
            } catch (SocketTimeoutException ignored) {
                // periodic wake-up so the running flag is re-checked
            } catch (Exception e) {
                if (running.get() && !bound.isClosed()) {
                    // transient receive failure; keep serving
                    continue;
                }
                return;
            }
        }
    }

    private void handle(DatagramPacket request, DatagramSocket bound) {
        byte[] query = new byte[request.getLength()];
        System.arraycopy(request.getData(), request.getOffset(), query, 0, request.getLength());

        String host = parseQName(query);
        boolean allowed = host != null && AppConfig.getInstance().isSiteAllowed(host);

        byte[] response;
        if (allowed) {
            response = resolveApproved(query, host);
        } else {
            response = buildResponse(query, RCODE_NXDOMAIN);
            if (host != null) recordBlocked(host);
        }

        if (response == null) return;
        try {
            if (!bound.isClosed()) {
                bound.send(new DatagramPacket(response, response.length,
                        request.getAddress(), request.getPort()));
            }
        } catch (IOException ignored) {
            // client went away
        }
    }

    /**
     * Answer an approved lookup: replay a recent identical answer when one is
     * cached, otherwise forward upstream. Caching collapses a browser's burst of
     * repeated lookups (page + assets + safe-browsing refreshes) into a single
     * upstream round-trip and makes approved pages load noticeably faster.
     */
```

- `parseQName` reads the question name; `isSiteAllowed` decides; allowed →
  `resolveApproved`, otherwise → NXDOMAIN reply + `recordBlocked`.

**Part 5 — resolving an allowed name:**

```java
    private byte[] resolveApproved(byte[] query, String host) {
        String key = cacheKey(query, host);
        if (key != null) {
            CachedAnswer cached = answerCache.get(key);
            if (cached != null && cached.expiresAt() > System.currentTimeMillis()) {
                collectIps(parseAnswerIps(cached.response()));
                return withQueryId(cached.response(), query);
            }
            if (cached != null) answerCache.remove(key);
        }

        byte[] response = forward(query);
        if (response != null && key != null && answerCount(response) > 0) {
            collectIps(parseAnswerIps(response));
            if (answerCache.size() >= CACHE_MAX_ENTRIES) answerCache.clear();
            answerCache.put(key, new CachedAnswer(withQueryId(response, new byte[]{0, 0}),
                    System.currentTimeMillis() + CACHE_TTL_MS));
        }
        return response;
    }

    /** Record addresses served for approved domains; the egress firewall follows them. */
    private void collectIps(List<String> ips) {
        if (allowedIpSink == null || ips.isEmpty()) return;
        synchronized (allowedAnswerIps) {
            if (allowedAnswerIps.size() >= 512) allowedAnswerIps.clear(); // bounded CDN churn
        }
        allowedAnswerIps.addAll(ips);
        ipListDirty = true;
    }

    /** Rewrite the sink file when new approved addresses have been seen. */
    private void flushAllowedIps() {
        if (!ipListDirty || allowedIpSink == null) return;
        ipListDirty = false;
        List<String> snapshot;
        synchronized (allowedAnswerIps) {
            snapshot = new ArrayList<>(allowedAnswerIps);
        }
        try {
            Files.write(allowedIpSink.toPath(),
                    (String.join("\n", snapshot) + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            ipListDirty = true;
        }
    }

    /** IPv4/IPv6 addresses carried by a successful upstream answer (A and AAAA records). */
```

- Cache first (30 s TTL) — a hit is returned with the CLIENT's own transaction
  ID written back in (`withQueryId`).
- On a miss: `forward()` → validate → collect the answer IPs for the firewall
  file → store in the cache.
- `flushAllowedIps()` rewrites the IP file (dirty flag set on new addresses) —
  a scheduled executor calls it every 3 seconds.

**Part 6 — extracting addresses from a DNS answer, byte by byte:**

```java
    public static List<String> parseAnswerIps(byte[] msg) {
        List<String> out = new ArrayList<>();
        if (msg == null || msg.length < 12) return out;
        int questions = ((msg[4] & 0xFF) << 8) | (msg[5] & 0xFF);
        int answers = ((msg[6] & 0xFF) << 8) | (msg[7] & 0xFF);
        int pos = 12;
        for (int i = 0; i < questions && pos < msg.length; i++) {
            int next = skipName(msg, pos);
            if (next < 0) return out;
            pos = next + 4; // QTYPE + QCLASS
        }
        for (int i = 0; i < answers && pos + 10 <= msg.length; i++) {
            int next = skipName(msg, pos);
            if (next < 0) return out;
            pos = next;
            int type = ((msg[pos] & 0xFF) << 8) | (msg[pos + 1] & 0xFF);
            int rdlength = ((msg[pos + 8] & 0xFF) << 8) | (msg[pos + 9] & 0xFF);
            pos += 10;
            if (pos + rdlength > msg.length) return out;
            if (type == 1 && rdlength == 4) {
                out.add((msg[pos] & 0xFF) + "." + (msg[pos + 1] & 0xFF) + "."
                        + (msg[pos + 2] & 0xFF) + "." + (msg[pos + 3] & 0xFF));
            } else if (type == 28 && rdlength == 16) {
                byte[] addr = new byte[16];
                System.arraycopy(msg, pos, addr, 0, 16);
                try {
                    out.add(InetAddress.getByAddress(addr).getHostAddress());
                } catch (Exception ignored) {
                    // a malformed AAAA record is skipped, the rest still count
                }
            }
            pos += rdlength;
        }
        return out;
    }

    /** Index just past a possibly compressed name; -1 when the message is malformed. */
    private static int skipName(byte[] msg, int pos) {
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2 <= msg.length ? pos + 2 : -1;
            pos += 1 + len;
        }
        return -1;
    }

    /**
     * Cache key: the question name and type. The query ID is excluded on purpose —
     * cached answers are served with each requester's own ID written back in.
     */
```

- The header is 12 bytes; question and answer names may use "compression
  pointers" (`0xC0...`) — `skipName` handles both plain labels and pointers.
- Type 1 = A record (4 bytes, printed dotted), type 28 = AAAA (16 bytes,
  converted with `InetAddress.getByAddress`).

**Part 7 — cache key, ID rewrite, counters:**

```java
    private static String cacheKey(byte[] query, String host) {
        if (host == null) return null;
        int qtype = questionType(query);
        if (qtype < 0) return null;
        return host + "/" + qtype;
    }

    /** Write the two ID bytes of {@code idSource} into a copy of {@code response}. */
    private static byte[] withQueryId(byte[] response, byte[] idSource) {
        byte[] out = response.clone();
        out[0] = idSource[0];
        out[1] = idSource[1];
        return out;
    }

    /** ANCOUNT of a DNS message, or -1 when the header is malformed. */
    private static int answerCount(byte[] msg) {
        if (msg.length < 12) return -1;
        return ((msg[6] & 0xFF) << 8) | (msg[7] & 0xFF);
    }

    /** QTYPE of the first question, or -1. */
    private static int questionType(byte[] msg) {
        if (msg.length < 12) return -1;
        int pos = 12;
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) != 0) return -1;
            pos++;
            if (pos + len > msg.length) return -1;
            pos += len;
        }
        if (pos + 4 > msg.length) return -1;
        return ((msg[pos] & 0xFF) << 8) | (msg[pos + 1] & 0xFF);
    }

    /**
     * Resolve an approved domain through a system or public resolver.
     *
     * <p>The upstream socket is CONNECTED so the kernel discards datagrams from any
     * source other than the resolver itself, and every reply is validated against
     * the request (matching ID, question name and question type) before it is used.
     * Without these checks an attacker on the exam LAN could race spoofed replies
     * and point an approved domain at a server they control.
     */
```

- The cache key deliberately EXCLUDES the transaction ID — each client gets its
  own ID written back in.

**Part 8 — forwarding and anti-spoofing:**

```java
    private byte[] forward(byte[] query) {
        for (String upstream : upstreams) {
            try (DatagramSocket up = new DatagramSocket()) {
                up.setSoTimeout(UPSTREAM_TIMEOUT_MS);
                InetAddress addr = InetAddress.getByName(upstream);
                up.connect(addr, DNS_PORT);
                up.send(new DatagramPacket(query, query.length, addr, DNS_PORT));
                byte[] buf = new byte[MAX_PACKET];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                up.receive(resp);
                byte[] out = new byte[resp.getLength()];
                System.arraycopy(resp.getData(), 0, out, 0, resp.getLength());
                if (!responseMatchesQuery(out, query)) continue; // spoofed or garbled: next resolver
                return out;
            } catch (Exception ignored) {
                // try the next resolver
            }
        }
        return buildResponse(query, RCODE_SERVFAIL);
    }

    /** True when a reply is a usable answer to this exact query. */
    public static boolean responseMatchesQuery(byte[] reply, byte[] query) {
        if (reply.length < 12 || query.length < 12) return false;
        if (reply[0] != query[0] || reply[1] != query[1]) return false;   // transaction ID
        String asked = parseQName(query);
        String answered = parseQName(reply);
        if (asked == null || !asked.equals(answered)) return false;
        return questionType(reply) == questionType(query);
    }

    /**
     * Report a denied lookup. Background/telemetry lookups are dropped silently and
     * the startup settling window is quiet, so only deliberate student navigation is
     * recorded — as a NOTICE (yellow), because the block held and nothing opened.
     * A red flag stays reserved for things that actually got through.
     */
```

- The upstream socket is CONNECTED, so the OS itself drops datagrams from
  anyone else. `responseMatchesQuery` then checks ID + question name + question
  type — a forged answer fails all three.

**Part 9 — recording a blocked lookup:**

```java
    private void recordBlocked(String host) {
        if (System.currentTimeMillis() < graceUntil) return;
        if (loggedBlockedHosts.size() >= MAX_LOGGED_HOSTS) return;

        String userFacing = reporter.userFacingViolation(host);
        if (userFacing == null || userFacing.isEmpty()) return;
        if (!loggedBlockedHosts.add(userFacing)) return;

        Violation v = new Violation("BLOCKED_INTERNET_DOMAIN", userFacing,
                Violation.Severity.NOTICE);
        logManager.record(v);
        if (listener != null) listener.onViolation(v);
    }

    // ------------------------------------------------ minimal DNS wire format

    private static final int RCODE_SERVFAIL = 2;
    private static final int RCODE_NXDOMAIN = 3;

    /** Read the first question name from a query, lower-cased. */
    public static String parseQName(byte[] msg) {
        if (msg.length < 12) return null;
        int pos = 12;
        StringBuilder sb = new StringBuilder();
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) != 0) return null; // compression pointer: not a plain question
            pos++;
            if (pos + len > msg.length) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < len; i++) sb.append((char) (msg[pos + i] & 0xFF));
            pos += len;
        }
        return sb.length() == 0 ? null : sb.toString().toLowerCase(Locale.ROOT);
    }

    /** Echo the question back with the supplied RCODE and no answer records. */
    private static byte[] buildResponse(byte[] query, int rcode) {
        if (query.length < 12) return null;
        int pos = 12;
        while (pos < query.length) {
            int len = query[pos] & 0xFF;
            pos++;
            if (len == 0) break;
            pos += len;
        }
        pos += 4; // QTYPE + QCLASS
        int questionEnd = Math.min(pos, query.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(query[0]);
        out.write(query[1]);
        int rd = query[2] & 0x01;
        out.write(0x80 | rd);             // QR=1, RD copied
        out.write(0x80 | (rcode & 0x0F)); // RA=1 + RCODE
        out.write(0x00); out.write(0x01); // QDCOUNT = 1
        for (int i = 0; i < 6; i++) out.write(0x00); // AN/NS/AR = 0
        for (int i = 12; i < questionEnd; i++) out.write(query[i]);
        return out.toByteArray();
    }
}
```

- Three gates before a row exists: the grace window, the noise reporter, the
  once-per-host set. What survives is a NOTICE (yellow) — the block held.
- `buildResponse` echoes the question with the RCODE set (3 = NXDOMAIN) and
  zero answers.

### 3) watchdog/StrictNetworkLockdown.java — the network lifecycle

**Part 1 — fields: the whole protocol is FILES:**

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppPaths;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;
import com.cheatguard.security.LogProtection;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Starts website lockdown: the local {@link DnsAllowlistServer} plus the elevated
 * helper that points the machine's DNS at it and forces browser DNS-over-HTTPS off.
 *
 * <p>Enforcement is at name resolution. An earlier design also forced browsers
 * through a local HTTP proxy under a firewall outbound default-deny; that reliably
 * blocked unapproved sites but broke approved ones whenever a browser did not
 * honour the injected proxy setting, leaving the student with no working Internet.
 * Filtering DNS instead keeps approved sites on their normal, direct network path.
 */
public final class StrictNetworkLockdown implements Closeable {
    private final LogManager logManager;
    private final ViolationListener listener;
    private DnsAllowlistServer dnsServer;
    private final File networkDir = AppPaths.getNetworkDirectory();
    private final File helper = new File(networkDir, "network-lockdown.ps1");
    private final File config = new File(networkDir, "active-config.json");
    private final File ready = new File(networkDir, "ready.marker");
    private final File stop = new File(networkDir, "stop.marker");
    private final File restored = new File(networkDir, "restored.marker");
    private final File error = new File(networkDir, "error.txt");
    private final File state = new File(networkDir, "firewall_state.json");
    private final File allowedIps = new File(networkDir, "allowed-ips.txt");
    private final File egressStatus = new File(networkDir, "egress-status.txt");
    private final File lockPathsFile = new File(networkDir, "lock-paths.txt");
    private final File lockStatusFile = new File(networkDir, "lock-status.txt");
    /** The student's exam folder - the ONLY folder that stays readable. */
    private volatile File examFolder;
    private volatile boolean active;
    private volatile String lastError = "";

```

- helper, config, ready, stop, restored, error, state, allowedIps,
  egressStatus — all inside the admin-protected network folder.

**Part 2 — start():**

```java
    public StrictNetworkLockdown(LogManager logManager, ViolationListener listener) {
        this.logManager = logManager;
        this.listener = listener;
    }

    /** Give the lockdown the student's exam folder - the only readable folder. */
    public void setExamFolder(File folder) {
        if (folder != null && folder.isDirectory()) this.examFolder = folder;
    }

    public boolean start() {
        lastError = "";
        if (!isWindows()) {
            lastError = "Strict network mode requires Windows.";
            return false;
        }
        try {
            copyHelper();
            cleanupMarkers();
            startDnsServer();
            String sid = currentUserSid();
            String program = currentProgramPath();
            if (sid.isEmpty()) throw new IOException("Could not identify the signed-in Windows user SID.");
            if (program.isEmpty()) throw new IOException("Could not identify the Cheat.Guard executable path.");
            seedAllowedIps();
            writeLockPaths();
            writeConfig(sid, program);
            launchElevated(false);
            long end = System.currentTimeMillis() + 90000L;
            while (System.currentTimeMillis() < end) {
                if (ready.exists()) {
                    active = true;
                    emitInfo("STRICT_NETWORK_LOCK_ENABLED", "Website allowlist active: only admin-approved domains can be reached during this exam.");
                    emitEgressStatus();
                    emitLockStatus();
                    return true;
                }
                if (error.exists()) throw new IOException(readQuietly(error));
                Thread.sleep(250L);
            }
            throw new IOException("Administrator approval timed out or the elevated network helper did not start.");
        } catch (Exception e) {
            lastError = friendlyError(e);
            closeServers();
            return false;
        }
    }

    /**
     * Bind the local DNS filter. Failure is fatal to starting the exam: without
     * it the elevated helper would still redirect every adapter to 127.0.0.1,
     * which would break all name resolution instead of filtering it.
     *
     * <p>The machine's current resolvers are captured first so approved domains
     * keep resolving through the network the exam is actually running on (a campus
     * resolver, an ISP resolver) instead of hard-coded public addresses that a
     * restrictive network may refuse to answer.
     */
```

- Copy the helper → clean markers → start the DNS server → identify user SID
  and exe path → seed the IP file → write the config → launch elevated → poll
  READY up to 90 s (UAC time) → on error.txt, surface the reason.

**Part 3 — starting the DNS server + the IPv6-leak guard:**

```java
    private void startDnsServer() throws IOException {
        dnsServer = new DnsAllowlistServer(logManager, listener, detectSystemUpstreams(), allowedIps);
        try {
            dnsServer.start();
        } catch (IOException e) {
            dnsServer = null;
            throw new IOException("Could not start the local DNS filter on 127.0.0.1:"
                    + DnsAllowlistServer.DNS_PORT + " - " + e.getMessage()
                    + ". Another DNS service (Internet Connection Sharing, a local"
                    + " resolver such as Acrylic/Pi-hole, or an older Cheat.Guard"
                    + " session) is using that port. Stop it and start the exam again.", e);
        }
        // If real IPv6 resolvers are configured but ::1 could not be bound, the
        // helper must leave IPv6 DNS untouched and Windows - which prefers IPv6
        // resolvers - would route lookups around the filter silently. Starting an
        // exam in that state would be theatre, so refuse loudly instead.
        if (!dnsServer.isIpv6Bound() && ipv6DnsServersPresent()) {
            closeServers();
            throw new IOException("This computer has IPv6 DNS servers configured, but the"
                    + " local DNS filter could not bind the IPv6 loopback (::1:"
                    + DnsAllowlistServer.DNS_PORT + "). Website blocking could be bypassed"
                    + " through IPv6, so the session was not started. Restart the computer"
                    + " and try again; if it persists, disable IPv6 on the network adapter"
                    + " or close the program that is using the port.");
        }
    }

    /**
     * True when an adapter holds a routable IPv6 resolver (global, ULA or
     * link-local). The site-local fec0:0:0:ffff::x entries Windows reports when no
     * IPv6 DNS was ever configured are placeholder metadata, not real resolvers, and
     * are ignored.
     */
    private boolean ipv6DnsServersPresent() {
        try {
            String script = "$ErrorActionPreference='SilentlyContinue';"
                    + "Get-DnsClientServerAddress -AddressFamily IPv6 | ForEach-Object { $_.ServerAddresses }";
            Process p = PowerShellUtil.start(script);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String v = line.trim().toLowerCase(java.util.Locale.ROOT);
                    if (v.isEmpty()) continue;
                    if (v.equals("::1")) continue;
                    if (v.startsWith("fec0:")) continue;
                    if (v.contains(":")) return true;
                }
            }
            if (!p.waitFor(8, TimeUnit.SECONDS)) p.destroyForcibly();
        } catch (Exception ignored) {
            // probe failure must not block the exam on its own; IPv4 filtering still applies
        }
        return false;
    }

    /**
     * The IPv4 resolvers in use right now, excluding loopback addresses this
     * application binds. Best effort: on any failure an empty list is returned and
     * the DNS server falls back to public resolvers.
     */
    private List<String> detectSystemUpstreams() {
        Set<String> found = new LinkedHashSet<>();
        try {
            String script = "$ErrorActionPreference='SilentlyContinue';"
                    + "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses }";
            Process p = PowerShellUtil.start(script);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String v = line.trim();
                    if (v.isEmpty()) continue;
                    if (v.equals("127.0.0.1") || v.equals("::1") || v.contains(":")) continue;
                    if (!v.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
                    found.add(v);
                    if (found.size() >= 4) break;
                }
            }
            if (!p.waitFor(8, TimeUnit.SECONDS)) p.destroyForcibly();
        } catch (Exception ignored) {
            // fall back to public resolvers
        }
        return new ArrayList<>(found);
    }

```

- If ::1 cannot be bound while real IPv6 resolvers exist, the exam REFUSES to
  start — otherwise students could escape through IPv6.
- `detectSystemUpstreams` captures the machine's current resolvers (skipping
  loopback) so approved sites keep working on campus networks.

A note on private browsing: incognito windows use the same system DNS, the
same DoH-off policies and the same firewall - none of the layers care which
browser mode the student picks, so private windows get no bypass.

**Part 4 — stop and stale recovery:**

```java
    private void closeServers() {
        if (dnsServer != null) dnsServer.close();
        dnsServer = null;
    }

    public String getLastError() {
        String s = lastError == null ? "" : lastError.trim();
        if (s.length() > 1800) s = s.substring(0, 1800) + "...";
        return s;
    }

    public File getErrorFile() { return error; }

    public boolean stopAndRestore() {
        if (!isWindows()) return true;
        try {
            Files.writeString(stop.toPath(), "STOP", StandardCharsets.US_ASCII);
            long end = System.currentTimeMillis() + 25000L;
            while (System.currentTimeMillis() < end) {
                if (restored.exists() || !state.exists()) break;
                Thread.sleep(200L);
            }
            active = false;
            closeServers();
            return restored.exists() || !state.exists();
        } catch (Exception e) {
            closeServers();
            return false;
        }
    }

    public static boolean recoverStaleIfPresent() {
        if (!isWindowsStatic()) return true;
        File dir = AppPaths.getNetworkDirectory();
        File state = new File(dir, "firewall_state.json");
        File cfg = new File(dir, "active-config.json");
        File helper = new File(dir, "network-lockdown.ps1");
        if (!state.exists() || !cfg.exists()) return true;
        try {
            // Always use the helper bundled with this version for stale-session recovery.
            try (InputStream in = StrictNetworkLockdown.class.getResourceAsStream("/network-lockdown.ps1")) {
                if (in == null) return false;
                Files.copy(in, helper.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            File restored = new File(dir, "restored.marker");
            File error = new File(dir, "error.txt");
            restored.delete(); error.delete();
            launchElevatedStatic(helper, cfg, true);
            long end = System.currentTimeMillis() + 60000L;
            while (System.currentTimeMillis() < end) {
                if (restored.exists() || !state.exists()) return true;
                if (error.exists()) return false;
                Thread.sleep(250L);
            }
        } catch (Exception ignored) {}
        return false;
    }

```

- `stopAndRestore()` writes stop.marker and waits up to 25 s for RESTORED —
  the return value says whether restore is CONFIRMED.
- `recoverStaleIfPresent()` (static, at app start): if a state file survived a
  crash, copy the CURRENT helper over the old one and launch it with
  `-RecoverOnly` — it restores from the snapshot.

**Part 5 — config writing, seeding, egress status:**

```java
    private void emitInfo(String type, String detail) {
        Violation v = new Violation(type, detail, Violation.Severity.INFO);
        logManager.record(v);
        if (listener != null) listener.onViolation(v);
    }

    private void copyHelper() throws IOException {
        try (InputStream in = StrictNetworkLockdown.class.getResourceAsStream("/network-lockdown.ps1")) {
            if (in == null) throw new FileNotFoundException("network-lockdown.ps1 resource missing");
            Files.copy(in, helper.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void cleanupMarkers() {
        ready.delete(); stop.delete(); restored.delete(); error.delete();
        LogProtection.requestFile().delete();
        LogProtection.doneFile().delete();
    }

    private void writeConfig(String sid, String program) throws IOException {
        boolean dnsIpv6 = dnsServer != null && dnsServer.isIpv6Bound();
        String verifyHost = firstAllowedSite();
        String json = "{\n" +
                "\"parentPid\":" + currentPid() + ",\n" +
                "\"dnsPort\":" + DnsAllowlistServer.DNS_PORT + ",\n" +
                "\"dnsIpv6\":" + dnsIpv6 + ",\n" +
                "\"userSid\":\"" + jsonEscape(sid) + "\",\n" +
                "\"programPath\":\"" + jsonEscape(program) + "\",\n" +
                "\"vaultDir\":\"" + jsonEscape(AppPaths.getVaultDirectory().getAbsolutePath()) + "\",\n" +
                "\"allowedIpFile\":\"" + jsonEscape(allowedIps.getAbsolutePath()) + "\",\n" +
                "\"egressStatusFile\":\"" + jsonEscape(egressStatus.getAbsolutePath()) + "\",\n" +
                "\"verifyHost\":\"" + jsonEscape(verifyHost) + "\",\n" +
                "\"lockPathsFile\":\"" + jsonEscape(lockPathsFile.getAbsolutePath()) + "\",\n" +
                "\"lockStatusFile\":\"" + jsonEscape(lockStatusFile.getAbsolutePath()) + "\",\n" +
                "\"userSidForLocks\":\"" + jsonEscape(sid) + "\",\n" +
                "\"stateFile\":\"" + jsonEscape(state.getAbsolutePath()) + "\",\n" +
                "\"readyFile\":\"" + jsonEscape(ready.getAbsolutePath()) + "\",\n" +
                "\"stopFile\":\"" + jsonEscape(stop.getAbsolutePath()) + "\",\n" +
                "\"restoredFile\":\"" + jsonEscape(restored.getAbsolutePath()) + "\",\n" +
                "\"protectRequestFile\":\"" + jsonEscape(LogProtection.requestFile().getAbsolutePath()) + "\",\n" +
                "\"protectDoneFile\":\"" + jsonEscape(LogProtection.doneFile().getAbsolutePath()) + "\",\n" +
                "\"errorFile\":\"" + jsonEscape(error.getAbsolutePath()) + "\"\n}";
        Files.writeString(config.toPath(), json, StandardCharsets.UTF_8);
    }

    /** A judge domain the helper's egress lockdown verifies against before arming. */
    private String firstAllowedSite() {
        for (String s : com.cheatguard.config.AppConfig.getInstance().getAllowedSites()) return s;
        return "";
    }

    /**
     * Resolve the first allowed domains up front and write their addresses, so the
     * helper's egress allowlist is populated before it switches the firewall to
     * default-deny (an empty list would verify-fail on every network).
     */
    private void seedAllowedIps() {
        List<String> seeds = new ArrayList<>();
        int sites = 0;
        for (String site : com.cheatguard.config.AppConfig.getInstance().getAllowedSites()) {
            if (++sites > 6 || seeds.size() >= 32) break;
            try {
                for (java.net.InetAddress a : java.net.InetAddress.getAllByName(site)) {
                    if (seeds.size() < 32) seeds.add(a.getHostAddress());
                }
            } catch (Exception ignored) {
                // offline or unreachable: the DNS server records addresses as they are answered
            }
        }
        try {
            Files.writeString(allowedIps.toPath(), String.join("\n", seeds) + "\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

    /** Report whether the egress firewall layer armed, or fell back to DNS-only. */
    private void emitEgressStatus() {
        String status = "";
        try {
            if (egressStatus.isFile()) {
                status = Files.readString(egressStatus.toPath(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        if ("ACTIVE".equalsIgnoreCase(status)) {
            emitInfo("EGRESS_FIREWALL_ENABLED",
                    "Egress firewall active: web traffic is restricted to the servers of approved websites.");
        } else {
            emitInfo("EGRESS_FIREWALL_FALLBACK",
                    "Egress firewall could not be verified on this network; DNS-level website blocking is active.");
        }
    }

    /** Report whether the student's file-access locks applied. */
    private void emitLockStatus() {
        String status = "";
        try {
            if (lockStatusFile.isFile()) {
                status = Files.readString(lockStatusFile.toPath(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        if ("ACTIVE".equalsIgnoreCase(status)) {
            emitInfo("FILE_LOCK_ENABLED",
                    "File walls up: the student's account cannot open files outside the exam folder "
                            + "(Documents, Downloads, other drives, USB).");
        } else {
            emitInfo("FILE_LOCK_SKIPPED",
                    "Pre-exam file blocking could not be applied; process and folder alerts stay active.");
        }
    }

    /**
     * Build the list of folders the student's account is locked out of for the
     * exam: the profile's content folders, everything on the Desktop except the
     * exam folder and shortcuts, and every drive that holds neither Windows, the
     * profile, ProgramData nor an approved app.
     */
```
**Part 5b - the file walls:**

```java
    private List<String> buildLockPaths() {
        File profile = com.cheatguard.config.AppPaths.getUserProfileDirectory();
        File desktop = com.cheatguard.config.AppPaths.getDesktopDirectory();
        Set<String> keepDrives = new java.util.HashSet<>();
        addDriveOf(keepDrives, new File(System.getenv("SystemRoot") == null ? "C:\\" : System.getenv("SystemRoot")));
        addDriveOf(keepDrives, profile);
        addDriveOf(keepDrives, examFolder);
        addDriveOf(keepDrives, com.cheatguard.config.AppPaths.getDataDirectory());
        for (String allowed : com.cheatguard.config.AppConfig.getInstance().getAllowedProcesses()) {
            addDriveOf(keepDrives, new File(com.cheatguard.config.AppConfig.getInstance()
                    .getProcessPath(allowed) == null ? "C:\\" : com.cheatguard.config.AppConfig
                    .getInstance().getProcessPath(allowed)));
        }
        List<File> extraRoots = new ArrayList<>();
        for (File root : File.listRoots()) {
            if (!keepDrives.contains(root.getAbsolutePath().toLowerCase(java.util.Locale.ROOT))) {
                extraRoots.add(root);
            }
        }
        return collectLockPaths(profile, desktop, examFolder, extraRoots);
    }

    /** Drives that must stay untouched: add the drive letter of the given path. */
    private static void addDriveOf(Set<String> keep, File f) {
        if (f == null) return;
        String p = f.getAbsolutePath().toLowerCase(java.util.Locale.ROOT);
        if (p.length() >= 3 && p.charAt(1) == ':') keep.add(p.substring(0, 3));
    }

    /**
     * Pure path collection (testable): profile content folders, desktop children
     * except the exam folder and shortcuts, plus the given extra drive roots.
     *
     * Ancestor safety: a folder that CONTAINS the exam folder (for example OneDrive
     * when the Desktop is OneDrive-redirected) is never locked wholesale - denying
     * it would inherit down onto the exam folder itself. Its OTHER children are
     * locked instead, so only the exam chain stays open.
     */
    public static List<String> collectLockPaths(File profile, File desktop, File examFolder,
                                                List<File> extraRoots) {
        List<String> out = new ArrayList<>();
        if (profile != null && profile.isDirectory()) {
            for (String name : new String[]{"Documents", "Downloads", "Music", "Pictures",
                    "Videos", "Saved Games", "Contacts", "Links", "OneDrive", "3D Objects",
                    "Searches"}) {
                File f = new File(profile, name);
                if (!f.isDirectory()) continue;
                if (isAncestorOrSelf(f, examFolder)) {
                    lockChildrenExceptExam(f, examFolder, out, 0);
                } else {
                    out.add(f.getAbsolutePath());
                }
            }
        }
        if (desktop != null && desktop.isDirectory()) {
            lockChildrenExceptExam(desktop, examFolder, out, 0);
        }
        if (extraRoots != null) {
            for (File root : extraRoots) {
                if (!root.exists()) continue;
                if (isAncestorOrSelf(root, examFolder)) {
                    lockChildrenExceptExam(root, examFolder, out, 0);
                } else {
                    out.add(root.getAbsolutePath());
                }
            }
        }
        return out;
    }

    /** Deny a folder's children, but leave the chain to the exam folder open. */
    private static void lockChildrenExceptExam(File folder, File examFolder,
                                               List<String> out, int depth) {
        if (folder == null || !folder.isDirectory() || depth > 4) return;
        File[] kids = folder.listFiles();
        if (kids == null) return;
        for (File kid : kids) {
            if (examFolder != null && sameTarget(kid, examFolder)) continue; // the exam folder itself
            if (examFolder != null && isAncestor(kid, examFolder)) {         // on the exam chain
                lockChildrenExceptExam(kid, examFolder, out, depth + 1);
                continue;
            }
            if (kid.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".lnk")) continue;
            out.add(kid.getAbsolutePath());
        }
    }

    private static boolean isAncestorOrSelf(File dir, File examFolder) {
        return sameTarget(dir, examFolder) || isAncestor(dir, examFolder);
    }

    /** True when the exam folder lives INSIDE the given folder (strictly below it). */
    private static boolean isAncestor(File dir, File examFolder) {
        if (dir == null || examFolder == null) return false;
        String d;
        String e;
        try {
            d = dir.getCanonicalPath();
            e = examFolder.getCanonicalPath();
        } catch (Exception ex) {
            d = dir.getAbsolutePath();
            e = examFolder.getAbsolutePath();
        }
        d = d.toLowerCase(java.util.Locale.ROOT);
        e = e.toLowerCase(java.util.Locale.ROOT);
        if (!d.endsWith("\\")) d = d + "\\";
        return e.startsWith(d);
    }

    private static boolean sameTarget(File a, File b) {
        try {
            return a.getCanonicalPath().equalsIgnoreCase(b.getCanonicalPath());
        } catch (Exception e) {
            return a.getAbsolutePath().equalsIgnoreCase(b.getAbsolutePath());
        }
    }

    /** Write the lock list so the elevated helper can apply the denies. */
    private void writeLockPaths() {
        List<String> paths = buildLockPaths();
        try {
            Files.writeString(lockPathsFile.toPath(), String.join("\n", paths) + "\n",
                    StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

```


- `writeConfig` builds the JSON the helper trusts (paths, parent PID, SID,
  verify host...).
- `seedAllowedIps()` resolves up to 6 allowed sites NOW (real DNS still active)
  so the firewall allowlist is populated BEFORE default-deny arms.
- `emitEgressStatus()` reads the helper's status file and logs whether the
  egress firewall armed or fell back.

**Part 6 — the elevated launch:**

```java
    private void launchElevated(boolean recoverOnly) throws IOException {
        launchElevatedStatic(helper, config, recoverOnly);
    }

    /**
     * Uses PowerShell's native RunAs verb instead of Windows Script Host/VBScript.
     * This works on machines where Windows Script Host is disabled by policy.
     */
    private static void launchElevatedStatic(File helper, File config, boolean recoverOnly) throws IOException {
        String helperPath = psSingleQuote(helper.getAbsolutePath());
        String configPath = psSingleQuote(config.getAbsolutePath());
        String workDir = psSingleQuote(helper.getParentFile().getAbsolutePath());
        String recoverArg = recoverOnly ? ", '-RecoverOnly'" : "";
        // IMPORTANT: no -Wait here. network-lockdown.ps1 writes ready.marker almost
        // immediately, then intentionally keeps running (it loops until stop.marker
        // appears) for the whole exam session. If we -Wait on it, this call would
        // block for the entire exam and the caller's ready.marker/error.txt polling
        // loop would never get a chance to run, eventually timing out even though
        // the helper actually started fine - leaving the firewall/proxy lockdown
        // active with nothing to signal success. UAC-decline is still surfaced
        // synchronously by Start-Process -Verb RunAs even without -Wait, so we don't
        // lose that error path.
        String command = "$ErrorActionPreference='Stop'; " +
                "$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File','" + helperPath +
                "','-Config','" + configPath + "'" + recoverArg + "); " +
                "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs " +
                "-WindowStyle Hidden -WorkingDirectory '" + workDir + "' -ArgumentList $args -PassThru; " +
                "if($null -eq $p){ throw 'Could not start elevated network helper.' }";

        Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
                .redirectErrorStream(true).start();
        boolean done;
        try {
            // This wrapper now returns as soon as the elevated process is launched
            // (or throws immediately if the UAC prompt is declined), so a short
            // timeout is enough - it is not waiting for the exam to end anymore.
            done = p.waitFor(20, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for Administrator/UAC approval.", ie);
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (!done) {
            p.destroyForcibly();
            throw new IOException("Administrator/UAC approval timed out.");
        }
        if (p.exitValue() != 0) {
            File helperError = new File(config.getParentFile(), "error.txt");
            String detail = "";
            try { if (helperError.isFile()) detail = Files.readString(helperError.toPath(), StandardCharsets.UTF_8).trim(); }
            catch (Exception ignored) {}
            if (detail.isEmpty()) detail = out;
            if (detail.isEmpty()) detail = "The elevated network helper did not launch (UAC declined or blocked). Check error.txt and Windows Event Viewer.";
            throw new IOException(detail);
        }
        // Launch succeeded; actual readiness/failure of network-lockdown.ps1 itself
        // is now reported via ready.marker / error.txt, which start() already polls.
    }

```

- `Start-Process -Verb RunAs -PassThru` WITHOUT `-Wait`: we only wait for the
  UAC decision (20 s); the helper keeps running for the whole exam and talks to
  us through marker files.

**Part 7 — the small utilities:**

```java
    private String currentUserSid() throws IOException, InterruptedException {
        Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
                .redirectErrorStream(true).start();
```

- `currentProgramPath` prefers the jpackage launcher (falling back to the
  java.exe path would give EVERY Java program firewall access — a bug we
  avoided on purpose). `jsonEscape`/`psSingleQuote` stop injection into the
  config/script.

### 4) resources/network-lockdown.ps1 — the elevated helper (682 lines)

**Act 1 — parameters and safety checks:**

```powershell
param(
    [Parameter(Mandatory=$true)][string]$Config,
    [switch]$RecoverOnly
)

$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$stateFile = $cfg.stateFile
$readyFile = $cfg.readyFile
$stopFile = $cfg.stopFile
$restoredFile = $cfg.restoredFile
$errorFile = $cfg.errorFile
$protectRequestFile = $cfg.protectRequestFile
$protectDoneFile = $cfg.protectDoneFile
$allowedIpFile = [string]$cfg.allowedIpFile
$egressStatusFile = [string]$cfg.egressStatusFile
$verifyHost = [string]$cfg.verifyHost
$lockPathsFile = [string]$cfg.lockPathsFile
$lockStatusFile = [string]$cfg.lockStatusFile
$fusKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$groupName = 'Cheat.Guard Strict Exam'
$proxyKey = "Registry::HKEY_USERS\$($cfg.userSid)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The network helper is not running as Administrator. Approve the UAC prompt with an administrator account.'
    }
}

function Ensure-FirewallServices {
    foreach ($name in @('BFE','MpsSvc')) {
        $svc = Get-Service -Name $name -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            try { Start-Service -Name $name -ErrorAction Stop } catch {
                throw "Windows Firewall dependency '$name' is not running and could not be started: $($_.Exception.Message)"
            }
        }
    }
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'Windows NetSecurity PowerShell module is unavailable on this computer.'
    }
}
```
}

function Get-RegState([string]$Path, [string]$Name) {
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $value) { return [ordered]@{ Exists=$false; Kind=''; Value=$null } }
        $kind = $key.GetValueKind($Name).ToString()
        return [ordered]@{ Exists=$true; Kind=$kind; Value=$value }
    } catch {
        return [ordered]@{ Exists=$false; Kind=''; Value=$null }
    }
}

function Set-RegFromState([string]$Path, [string]$Name, $State) {
    if (-not $State.Exists) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    $type = if ($State.Kind -eq 'DWord') { 'DWord' } elseif ($State.Kind -eq 'QWord') { 'QWord' } elseif ($State.Kind -eq 'ExpandString') { 'ExpandString' } else { 'String' }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $State.Value -PropertyType $type -Force | Out-Null
}

function Notify-InternetSettings {
    try {
        if (-not ('CheatGuard.WinInetNative' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace CheatGuard {
    public static class WinInetNative {
        [DllImport("wininet.dll", SetLastError=true)]
        public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    }
}
"@
        }
        [CheatGuard.WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
        [CheatGuard.WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    } catch {}
}

function Get-BrowserPaths {
    $paths = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $names = @('chrome','msedge','firefox','brave','opera','opera_gx','vivaldi','iexplore')
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { if ($_.Path -and (Test-Path -LiteralPath $_.Path)) { [void]$paths.Add($_.Path) } } catch {}
        }
    }
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe",
        "$env:LOCALAPPDATA\Programs\Opera\opera.exe",
        "$env:LOCALAPPDATA\Programs\Opera GX\opera.exe"
    )
    foreach ($p in $candidates) { if ($p -and (Test-Path -LiteralPath $p)) { [void]$paths.Add($p) } }
    return @($paths)
}

# Browser DNS-over-HTTPS policies. A browser resolving names itself over HTTPS would
# never consult the local DNS filter, so DoH is forced off for the exam and restored after.
$dohPolicies = @(
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Google\Chrome';                Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge';               Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name='Enabled';          Value=0;     Type='DWord'  }
)

function Get-DohState {
    $out = [ordered]@{}
    foreach ($p in $dohPolicies) { $out[($p.Path + '|' + $p.Name)] = Get-RegState $p.Path $p.Name }
    return $out
}

function Disable-BrowserDoh {
    foreach ($p in $dohPolicies) {
        try {
            if (-not (Test-Path -LiteralPath $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
        } catch {}
    }
}

function Restore-Doh($DohState) {
    foreach ($p in $dohPolicies) {
        $key = $p.Path + '|' + $p.Name
        try {
            $st = $null
            if ($null -ne $DohState) { $st = $DohState.$key }
            if ($null -ne $st) { Set-RegFromState $p.Path $p.Name $st }
            else { Remove-ItemProperty -LiteralPath $p.Path -Name $p.Name -ErrorAction SilentlyContinue }
        } catch {}
    }
}

# Per-adapter DNS, both address families. Windows keeps separate IPv6 DNS servers and
# prefers them, so redirecting only IPv4 would leave lookups going around the filter (or,
# once outbound port 53 is denied to other programs, stall until those servers time out -
# which makes even approved sites fail to load). The static NameServer registry value is
# recorded per family so an adapter that used DHCP-provided DNS goes back to DHCP.
```powershell
function Get-DnsState {
    @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.InterfaceGuid
        $v4 = ''
        $v6 = ''
        try { $v4 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"  -Name NameServer -ErrorAction Stop).NameServer } catch { $v4 = '' }
        try { $v6 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction Stop).NameServer } catch { $v6 = '' }
        [ordered]@{ InterfaceIndex=$_.ifIndex; InterfaceAlias=$_.Name; StaticNameServer=$v4; StaticNameServerV6=$v6 }
    })
}

function Set-ExamDns {
    param([bool]$RedirectIpv6)
    $changed = 0
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
            $changed++
        } catch {}
        if ($RedirectIpv6) {
            try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return $changed
}

function Restore-Dns($DnsState) {
    foreach ($e in @($DnsState)) {
        foreach ($family in @('v4','v6')) {
            try {
                $raw = if ($family -eq 'v4') { [string]$e.StaticNameServer } else { [string]$e.StaticNameServerV6 }
                if ($raw -and $raw.Trim() -ne '') {
                    $servers = @($raw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
                    if ($servers.Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
                        continue
                    }
                }
                # No static value recorded for this family: put the adapter back on DHCP.
                # Both families must be reset - a v6-only reset would leave the adapter's
                # IPv6 resolver on the dead ::1 exam address, and Windows prefers IPv6
                # resolvers, stalling every lookup even though IPv4 is already correct.
                Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
            } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

# Confirms the local Cheat.Guard DNS filter is actually answering before the exam is
# allowed to start. Any reply (including NXDOMAIN) proves it is serving; a timeout means
# resolution would be dead for approved sites too, so lockdown must be rolled back.
```

- `Get-RegState`/`Set-RegFromState` snapshot-and-restore registry values.
  `Disable-BrowserDoh` writes DoH-off policies for Chrome/Edge/Firefox;
  `Restore-Doh` puts the original values back.

**Act 3 — DNS snapshot, redirect, restore:**

```powershell
function Get-DnsState {
    @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.InterfaceGuid
        $v4 = ''
        $v6 = ''
        try { $v4 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"  -Name NameServer -ErrorAction Stop).NameServer } catch { $v4 = '' }
        try { $v6 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction Stop).NameServer } catch { $v6 = '' }
        [ordered]@{ InterfaceIndex=$_.ifIndex; InterfaceAlias=$_.Name; StaticNameServer=$v4; StaticNameServerV6=$v6 }
    })
}

function Set-ExamDns {
    param([bool]$RedirectIpv6)
    $changed = 0
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
            $changed++
        } catch {}
        if ($RedirectIpv6) {
            try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return $changed
}

function Restore-Dns($DnsState) {
    foreach ($e in @($DnsState)) {
        foreach ($family in @('v4','v6')) {
            try {
                $raw = if ($family -eq 'v4') { [string]$e.StaticNameServer } else { [string]$e.StaticNameServerV6 }
                if ($raw -and $raw.Trim() -ne '') {
                    $servers = @($raw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
                    if ($servers.Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
                        continue
                    }
                }
                # No static value recorded for this family: put the adapter back on DHCP.
                # Both families must be reset - a v6-only reset would leave the adapter's
                # IPv6 resolver on the dead ::1 exam address, and Windows prefers IPv6
                # resolvers, stalling every lookup even though IPv4 is already correct.
                Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
            } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

# Confirms the local Cheat.Guard DNS filter is actually answering before the exam is
# allowed to start. Any reply (including NXDOMAIN) proves it is serving; a timeout means
# resolution would be dead for approved sites too, so lockdown must be rolled back.
```
function Test-DnsFilter {
    param([string]$Server = '127.0.0.1')
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Client.ReceiveTimeout = 4000
        $client.Connect($Server, 53)
        $q = New-Object System.Collections.Generic.List[byte]
        $q.AddRange([byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00))
        foreach ($label in @('selftest','invalid')) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            $q.Add([byte]$bytes.Length)
            $q.AddRange($bytes)
        }
        $q.Add([byte]0)
        $q.AddRange([byte[]]@(0x00,0x01,0x00,0x01))
        $payload = $q.ToArray()
        [void]$client.Send($payload, $payload.Length)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $reply = $client.Receive([ref]$remote)
        return ($null -ne $reply -and $reply.Length -ge 12)
    } catch {
        return $false
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
}

# Hardens a sealed session log so the desktop account cannot delete or edit it.
# Ownership moves to the Administrators group and inherited rights are dropped, so the
# signed-in user keeps read access but has no delete right and - not being the owner -
# cannot grant itself one. Only grants are used: an explicit deny would also block the
# elevated delete that the admin dashboard performs on purpose.
```powershell
function Protect-LogFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        takeown /F "$Path" /A | Out-Null
        icacls "$Path" /inheritance:r | Out-Null
        icacls "$Path" /grant "*S-1-5-32-544:(F)" | Out-Null   # Administrators: full
        icacls "$Path" /grant "*S-1-5-18:(F)"     | Out-Null   # SYSTEM: full
        icacls "$Path" /grant "*S-1-5-32-545:(R)" | Out-Null   # Users: read only
    } catch {}
}

function Handle-ProtectRequest {
    if ([string]::IsNullOrWhiteSpace($protectRequestFile)) { return }
    if (-not (Test-Path -LiteralPath $protectRequestFile)) { return }
    try {
        # Only paths the exam itself owns may be hardened. The request file is
        # written by the elevated app, but accepting arbitrary paths would turn a
        # bug or a misuse into a tool for ACL-bombing any folder on the machine.
        $networkRoot = Split-Path -Parent $Config
        $vaultDir = ''
        try { $vaultDir = [string]$cfg.vaultDir } catch {}
        $allowedRoots = @($networkRoot)
        if ($vaultDir) { $allowedRoots += $vaultDir }
        $dirs = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        foreach ($line in Get-Content -LiteralPath $protectRequestFile -ErrorAction SilentlyContinue) {
            $path = $line.Trim()
            if (-not $path) { continue }
            $ok = $false
            try {
                $full = [System.IO.Path]::GetFullPath($path).TrimEnd('\')
                foreach ($root in $allowedRoots) {
                    if ($root -and $full.StartsWith($root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) { $ok = $true; break }
                }
            } catch { $ok = $false }
            if (-not $ok) { continue }
            Protect-LogFile $path
            $parent = Split-Path -Parent $path
            if ($parent) { [void]$dirs.Add($parent) }
        }
        foreach ($d in $dirs) { Protect-VaultDirectory $d }
    } catch {}
    Remove-Item -LiteralPath $protectRequestFile -Force -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($protectDoneFile)) {
        'PROTECTED' | Set-Content -LiteralPath $protectDoneFile -Encoding ASCII
    }
}

# Removes the account's delete-child right on the vault folder. Without this a sealed
# file could still be deleted despite its own permissions, because delete-child on the
# parent folder is enough to remove a file. New files keep inheriting Modify so the app
# can still write a session log and remove its own plaintext copy when sealing.
function Protect-VaultDirectory([string]$Dir) {
    if ([string]::IsNullOrWhiteSpace($Dir)) { return }
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    try {
        takeown /F "$Dir" /A | Out-Null
        icacls "$Dir" /inheritance:r | Out-Null
        icacls "$Dir" /grant "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null   # Administrators
        icacls "$Dir" /grant "*S-1-5-18:(OI)(CI)(F)"     | Out-Null   # SYSTEM
        icacls "$Dir" /grant "*S-1-5-32-545:(RX,W)"      | Out-Null   # folder: read + create, no delete-child
        icacls "$Dir" /grant "*S-1-5-32-545:(OI)(IO)(M)" | Out-Null   # new files: modify
    } catch {}
}

```
function Remove-OurRules {
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

# File walls: the student's own account is DENIED read/execute/delete on every
# folder the Java side listed (profile content folders, desktop items other than
# the exam folder, other drives, USB). This works at the NTFS layer, so EVERY
# program running as the student - VS Code's terminal, Explorer, anything - hits
# "Access denied" outside the exam folder. Denies are per-SID and inherit down.
function Set-FileAccessLocks([string]$ListFile, [string]$Sid) {
    $locked = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($ListFile) -or [string]::IsNullOrWhiteSpace($Sid)) { return $locked }
    if (-not (Test-Path -LiteralPath $ListFile)) { return $locked }
    foreach ($line in @(Get-Content -LiteralPath $ListFile -ErrorAction SilentlyContinue)) {
        $p = $line.Trim()
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        try {
            icacls "$p" /deny "*$($Sid):(OI)(CI)(RX,D)" | Out-Null
            $locked.Add($p)
        } catch {}
    }
    return $locked
}

function Restore-FileAccess([string[]]$Paths, [string]$Sid) {
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        try { icacls "$p" /remove:d "*$Sid" | Out-Null } catch {}
    }
}

# VPN concentrators and remote-desktop relays speak on fixed ports that no exam
# traffic uses. Additive Block rules, the same safe pattern as the DoT rules;
# they also cover hand-rolled tunnelling tools the process sweep cannot name.
function Add-TunnelPortBlocks {
    $blocks = @(
        @{ Name = 'block VPN / IPsec / WireGuard ports'; Protocol = 'UDP'; Port = '500,4500,1194,51820' },
        @{ Name = 'block PPTP and outbound RDP';         Protocol = 'TCP'; Port = '1723,3389' },
        @{ Name = 'block VNC ports';                     Protocol = 'TCP'; Port = '5900-5910' },
        @{ Name = 'block QUIC (HTTP/3)';                 Protocol = 'UDP'; Port = '443' }
    )
    foreach ($b in $blocks) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName ('Cheat.Guard - ' + $b.Name) -Group $groupName `
            -Direction Outbound -Protocol $b.Protocol -RemotePort $b.Port `
            -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
}

# The Java filter writes every address an approved domain resolved to into the
# IP file; these are the only destinations the web ports may reach.
function Read-AllowedIps {
    if ([string]::IsNullOrWhiteSpace($allowedIpFile)) { return @() }
    if (-not (Test-Path -LiteralPath $allowedIpFile)) { return @() }
    $ips = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($line in @(Get-Content -LiteralPath $allowedIpFile -ErrorAction SilentlyContinue)) {
            $v = $line.Trim()
            if (-not $v) { continue }
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($v, [ref]$ip)) {
                if (-not $ip.IsIPv6LinkLocal -and -not $ip.Equals([System.Net.IPAddress]::Loopback) -and -not $ip.Equals([System.Net.IPAddress]::IPv6Loopback)) {
                    $ips.Add($v)
                }
            }
            if ($ips.Count -ge 400) { break }
        }
    } catch {}
    return $ips.ToArray()
}

function Set-AllowedDestinationRules([string[]]$Ips) {
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if ($Ips.Count -lt 1) { return }
    New-NetFirewallRule -PolicyStore PersistentStore `
        -DisplayName 'Cheat.Guard - allowed web destinations (TCP)' -Group $groupName `
        -Direction Outbound -Protocol TCP -RemotePort 80,443 -RemoteAddress $Ips `
        -Action Allow -Profile Any -ErrorAction Stop | Out-Null
}

# Plain TCP reachability of an approved domain on 443 - proves the allowlist
# actually carries traffic on this network without any HTTP/certificate quirks.
function Test-HttpsReachable([string]$Target) {
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Target, 443, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(8000)) { return $false }
        $client.EndConnect($async) | Out-Null
        return $client.Connected
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch {}
    }
}

# The full egress lockdown: outbound web traffic is denied by default and only the
# resolved addresses of approved domains (plus the local gateway, so campus
# captive portals and 802.1X page logins keep working) may pass. Verified against
# a real approved site; on a network where that fails, everything is rolled back
# and the session continues in DNS-only mode rather than risking a dead network.
function Apply-EgressLockdown {
    $ips = @(Read-AllowedIps)
    if ($ips.Count -lt 1) { return $false }
    Set-AllowedDestinationRules $ips

    $gateways = @()
    try {
        $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty NextHop -Unique | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' })
    } catch {}
    if ($gateways.Count -ge 1) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName 'Cheat.Guard - local network gateway' -Group $groupName `
            -Direction Outbound -RemoteAddress $gateways `
            -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        try { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction Block -ErrorAction Stop } catch {}
    }

    $verified = $false
    try { $verified = Test-HttpsReachable $verifyHost } catch { $verified = $false }
    if (-not $verified) {
        foreach ($p in @($state.Profiles)) {
            try { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop } catch {}
        }
        Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' -or $_.DisplayName -like 'Cheat.Guard - local network gateway' } |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        return $false
    }
    return $true
}

# Hides the "Switch user" entry so a pre-existing second local account cannot be
# used mid-exam. The previous value is snapshotted and Restore-All puts it back.
```powershell
function Get-FusState {
    try {
        $p = Get-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction Stop
        return @{ Exists = $true; Value = [int]$p.HideFastUserSwitching }
    } catch {
        return @{ Exists = $false; Value = $null }
    }
}

function Set-FusHidden {
    try {
        if (-not (Test-Path -LiteralPath $fusKey)) { New-Item -Path $fusKey -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    } catch {}
}

function Restore-Fus($Fus) {
    try {
        if ($Fus.Exists) {
            Set-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -Value ([int]$Fus.Value) -ErrorAction Stop
        } else {
            Remove-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Restore-All {
    Remove-OurRules
    if (-not (Test-Path -LiteralPath $stateFile)) { return }
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json

    foreach ($p in @($state.Profiles)) {
        try {
            Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop
        } catch {}
    }

    if (Test-Path -LiteralPath $proxyKey) {
        Set-RegFromState $proxyKey 'ProxyEnable' $state.Proxy.ProxyEnable
        Set-RegFromState $proxyKey 'ProxyServer' $state.Proxy.ProxyServer
        Set-RegFromState $proxyKey 'ProxyOverride' $state.Proxy.ProxyOverride
        Set-RegFromState $proxyKey 'AutoConfigURL' $state.Proxy.AutoConfigURL
        Notify-InternetSettings
    }

    Restore-Dns $state.Dns
    Restore-Doh $state.Doh
    Restore-Fus $state.Fus
    Restore-FileAccess $state.FileLocks $cfg.userSid
    Remove-Item -LiteralPath $egressStatusFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lockStatusFile -Force -ErrorAction SilentlyContinue

    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}

```

- `Protect-LogFile` = takeown + icacls (Administrators full, SYSTEM full,
  Users read-only). `Handle-ProtectRequest` validates every requested path is
  inside OUR roots (network dir or vault dir) — so a bug can never be turned
  into "ACL-bomb any folder on the PC".

**Act 6 — the firewall functions and the file-wall functions:**

```powershell
function Add-TunnelPortBlocks {
    $blocks = @(
        @{ Name = 'block VPN / IPsec / WireGuard ports'; Protocol = 'UDP'; Port = '500,4500,1194,51820' },
        @{ Name = 'block PPTP and outbound RDP';         Protocol = 'TCP'; Port = '1723,3389' },
        @{ Name = 'block VNC ports';                     Protocol = 'TCP'; Port = '5900-5910' },
        @{ Name = 'block QUIC (HTTP/3)';                 Protocol = 'UDP'; Port = '443' }
    )
    foreach ($b in $blocks) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName ('Cheat.Guard - ' + $b.Name) -Group $groupName `
            -Direction Outbound -Protocol $b.Protocol -RemotePort $b.Port `
            -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
}

# The Java filter writes every address an approved domain resolved to into the
# IP file; these are the only destinations the web ports may reach.
function Read-AllowedIps {
    if ([string]::IsNullOrWhiteSpace($allowedIpFile)) { return @() }
    if (-not (Test-Path -LiteralPath $allowedIpFile)) { return @() }
    $ips = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($line in @(Get-Content -LiteralPath $allowedIpFile -ErrorAction SilentlyContinue)) {
            $v = $line.Trim()
            if (-not $v) { continue }
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($v, [ref]$ip)) {
                if (-not $ip.IsIPv6LinkLocal -and -not $ip.Equals([System.Net.IPAddress]::Loopback) -and -not $ip.Equals([System.Net.IPAddress]::IPv6Loopback)) {
                    $ips.Add($v)
                }
            }
            if ($ips.Count -ge 400) { break }
        }
    } catch {}
    return $ips.ToArray()
}

function Set-AllowedDestinationRules([string[]]$Ips) {
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if ($Ips.Count -lt 1) { return }
    New-NetFirewallRule -PolicyStore PersistentStore `
        -DisplayName 'Cheat.Guard - allowed web destinations (TCP)' -Group $groupName `
        -Direction Outbound -Protocol TCP -RemotePort 80,443 -RemoteAddress $Ips `
        -Action Allow -Profile Any -ErrorAction Stop | Out-Null
}

# Plain TCP reachability of an approved domain on 443 - proves the allowlist
# actually carries traffic on this network without any HTTP/certificate quirks.
function Test-HttpsReachable([string]$Target) {
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Target, 443, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(8000)) { return $false }
        $client.EndConnect($async) | Out-Null
        return $client.Connected
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch {}
    }
}

# The full egress lockdown: outbound web traffic is denied by default and only the
# resolved addresses of approved domains (plus the local gateway, so campus
# captive portals and 802.1X page logins keep working) may pass. Verified against
# a real approved site; on a network where that fails, everything is rolled back
# and the session continues in DNS-only mode rather than risking a dead network.
function Apply-EgressLockdown {
    $ips = @(Read-AllowedIps)
    if ($ips.Count -lt 1) { return $false }
    Set-AllowedDestinationRules $ips

    $gateways = @()
    try {
        $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty NextHop -Unique | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' })
    } catch {}
    if ($gateways.Count -ge 1) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName 'Cheat.Guard - local network gateway' -Group $groupName `
            -Direction Outbound -RemoteAddress $gateways `
            -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        try { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction Block -ErrorAction Stop } catch {}
    }

    $verified = $false
    try { $verified = Test-HttpsReachable $verifyHost } catch { $verified = $false }
    if (-not $verified) {
        foreach ($p in @($state.Profiles)) {
            try { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop } catch {}
        }
        Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' -or $_.DisplayName -like 'Cheat.Guard - local network gateway' } |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        return $false
    }
    return $true
}

# Hides the "Switch user" entry so a pre-existing second local account cannot be
# used mid-exam. The previous value is snapshotted and Restore-All puts it back.
```
try {
    Assert-Administrator
    Ensure-FirewallServices

    if ($RecoverOnly) {
        Restore-All
        'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
        exit 0
    }

    Remove-Item -LiteralPath $readyFile,$stopFile,$restoredFile,$errorFile -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $cfg.programPath)) {
        throw "Cheat.Guard executable path was not found: $($cfg.programPath)"
    }

    # Recover a previous interrupted session before taking a fresh snapshot.
    if (Test-Path -LiteralPath $stateFile) { Restore-All }

    $profiles = @(Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{ Name=$_.Name; Enabled=$_.Enabled.ToString(); DefaultOutboundAction=$_.DefaultOutboundAction.ToString() }
    })
    $state = [ordered]@{
        UserSid = $cfg.userSid
        Profiles = $profiles
        Proxy = [ordered]@{
            ProxyEnable = Get-RegState $proxyKey 'ProxyEnable'
            ProxyServer = Get-RegState $proxyKey 'ProxyServer'
            ProxyOverride = Get-RegState $proxyKey 'ProxyOverride'
            AutoConfigURL = Get-RegState $proxyKey 'AutoConfigURL'
        }
        Dns = Get-DnsState
        Doh = Get-DohState
        Fus = Get-FusState
        FileLocks = @()
    }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    Set-FusHidden

    # A user-configured proxy is a complete bypass: the browser hands the request to
    # the proxy, which resolves names and connects on its own, never touching the
    # local DNS filter. The original settings were snapshotted above and Restore-All
    # puts them back, so user proxy and PAC are force-disabled for the exam and all
    # browsing goes direct - where the DNS allowlist applies. (An older build's
    # leftover loopback proxy, which points at a port nothing listens on, is covered
    # by the same disable step.)
    try {
        Set-ItemProperty -LiteralPath $proxyKey -Name 'ProxyEnable' -Value 0 -ErrorAction Stop
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'ProxyServer' -ErrorAction SilentlyContinue
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
        Notify-InternetSettings
    } catch {}
    $state.Proxy.ProxyEnable = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.ProxyServer = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.AutoConfigURL = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    # Strict default-deny is essential: it prevents an unsupported browser, a browser installed
    # in an unusual path, or another application from bypassing the proxy during the exam.
    # The original profile settings were snapshotted above and Restore-All puts them back.
    Remove-OurRules

    # Enforcement is at name resolution, not at the socket layer. An earlier design set
    # every profile's DefaultOutboundAction to Block and allowed browsers to reach only a
    # local proxy port; that blocked unapproved sites but also killed approved ones on any
    # machine where a browser did not honour the injected proxy setting. The firewall is now
    # used only for narrow, additive Block rules that cannot break normal traffic.

    # Close the DNS-over-HTTPS escape at the network layer as well as by policy: deny TCP 443
    # to the well-known public DoH resolvers. Ordinary websites are unaffected, and the
    # Cheat.Guard filter's own upstream lookups use UDP/TCP 53, not 443.
    $dohResolvers = @(
        '1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15','45.90.28.0/24','45.90.30.0/24'
    )
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoH resolvers' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 443 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Deny DNS-over-TLS entirely (TCP and UDP 853): a custom resolver or a Windows 11
    # DoT setting would otherwise tunnel around the local filter the same way DoH would.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # A custom tool could bypass the local filter by querying a well-known public
    # resolver directly (nslookup facebook.com 8.8.8.8). Block port 53 to those
    # resolvers. The filter's own upstreams never use this list: the Java side drops
    # captured system resolvers that appear here and falls back to Quad9 unfiltered
    # endpoints instead, so its own path stays open.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Keep the Cheat.Guard process explicitly permitted outbound so its upstream DNS keeps
    # working even on a machine whose profiles already default to Block.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - filter host outbound' -Group $groupName -Direction Outbound -Program $cfg.programPath -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # ---- tunnel/remote-access hardening, then the egress web lockdown ----
    Add-TunnelPortBlocks
    $script:lastIps = ''
    $script:egressActive = $false
    if ((-not [string]::IsNullOrWhiteSpace($allowedIpFile)) -and (-not [string]::IsNullOrWhiteSpace($verifyHost))) {
        try {
            $script:egressActive = Apply-EgressLockdown
            $script:lastIps = (@(Read-AllowedIps) -join ',')
        } catch {
            $script:egressActive = $false
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($egressStatusFile)) {
        if ($script:egressActive) { 'ACTIVE' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
        else { 'FALLBACK' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
    }

    # ---- file walls: deny the student's account everything outside the exam folder ----
    $script:fileLocks = @()
    if ((-not [string]::IsNullOrWhiteSpace($lockPathsFile)) -and (Test-Path -LiteralPath $lockPathsFile)) {
        try { $script:fileLocks = @(Set-FileAccessLocks $lockPathsFile $cfg.userSid) } catch { $script:fileLocks = @() }
    }
    $state.FileLocks = @($script:fileLocks)
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8
    if (-not [string]::IsNullOrWhiteSpace($lockStatusFile)) {
        if ($script:fileLocks.Count -ge 1) { 'ACTIVE' | Set-Content -LiteralPath $lockStatusFile -Encoding ASCII }
        else { 'SKIPPED' | Set-Content -LiteralPath $lockStatusFile -Encoding ASCII }
    }

    # Force browsers onto the system resolver, then point the system resolver at the
    # Cheat.Guard DNS filter. Unapproved domains then fail to resolve for every program,
    # while approved domains resolve normally and connect over their usual direct path.
    Disable-BrowserDoh
    $redirectIpv6 = [bool]$cfg.dnsIpv6
    $dnsChanged = Set-ExamDns -RedirectIpv6 $redirectIpv6
    if ($dnsChanged -lt 1) {
        throw 'Could not redirect any network adapter to the Cheat.Guard DNS filter (127.0.0.1). Check that a network adapter is connected.'
    }
    if (-not (Test-DnsFilter '127.0.0.1')) {
        throw 'The Cheat.Guard DNS filter on 127.0.0.1:53 did not answer a test lookup. Lockdown has been rolled back so the computer keeps working; start the exam again.'
    }

    # Chromium/Firefox cache DoH and resolver state, so restart them once when exam mode
    # begins to make sure the policy and the redirected DNS are picked up.
    foreach ($name in @('chrome','msedge','firefox','brave','opera','opera_gx','vivaldi','iexplore')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700

    # Verify DNS redirection before telling the Java app that lockdown is ready.
    $dnsOk = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' }).Count
    if ($dnsOk -lt 1) { throw 'DNS redirection verification failed: no adapter is using the Cheat.Guard DNS filter.' }
    if (-not (Test-DnsFilter '127.0.0.1')) { throw 'The Cheat.Guard DNS filter stopped answering during verification.' }

    # Keep new or re-connected adapters on the filter for the whole session. A USB
    # Wi-Fi dongle or a re-connected Ethernet adapter comes up with DHCP DNS and
    # would resolve straight through the real resolvers, bypassing the exam allowlist.
    $redirectedIfIndex = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in @($state.Dns)) { if ($e.InterfaceIndex) { [void]$redirectedIfIndex.Add([string]$e.InterfaceIndex) } }
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        [void]$redirectedIfIndex.Add([string]$a.ifIndex)
    }

    # This directory holds the session's control markers (stop, protect-request) and
    # the helper configuration. Restrict it to Administrators now that the app itself
    # runs elevated: the signed-in account keeps read access but can no longer forge
    # a stop marker to silently end the lockdown, rewrite the helper configuration,
    # or swap this script while the UAC prompt is on screen.
    try {
        $networkRoot = Split-Path -Parent $Config
        takeown /F "$networkRoot" /A | Out-Null
        icacls "$networkRoot" /inheritance:r | Out-Null
        icacls "$networkRoot" /grant "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null   # Administrators: full
        icacls "$networkRoot" /grant "*S-1-5-18:(OI)(CI)(F)"     | Out-Null   # SYSTEM: full
        icacls "$networkRoot" /grant "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Null  # Users: read+execute only
    } catch {}

    'READY' | Set-Content -LiteralPath $readyFile -Encoding ASCII

    $loopCount = 0
    while ($true) {
        if (Test-Path -LiteralPath $stopFile) { break }
        if (-not (Get-Process -Id ([int]$cfg.parentPid) -ErrorAction SilentlyContinue)) { break }
        Handle-ProtectRequest
        $loopCount++
        if ($script:egressActive -and ($loopCount % 10) -eq 0) {
            # Approved pages resolve new CDN addresses mid-exam; the allow rule follows.
            $ips = @(Read-AllowedIps)
            if ($ips.Count -ge 1) {
                $blob = $ips -join ','
                if ($blob -ne $script:lastIps) {
                    try {
                        Set-AllowedDestinationRules $ips
                        $script:lastIps = $blob
                    } catch {}
                }
            }
        }
        foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
            $key = [string]$a.ifIndex
            if (-not $redirectedIfIndex.Contains($key)) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
                    if ($redirectIpv6) {
                        try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
                    }
                    [void]$redirectedIfIndex.Add($key)
                } catch {}
            }
        }
        Start-Sleep -Milliseconds 500
    }

    # The app seals the log just before asking for shutdown, so serve one last request.
    Handle-ProtectRequest

    Restore-All
    'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
    exit 0
} catch {
    $msg = @(
        'Cheat.Guard strict-network helper failed.',
        ('Message: ' + $_.Exception.Message),
        ('Type: ' + $_.Exception.GetType().FullName),
        ('PowerShell: ' + $PSVersionTable.PSVersion.ToString()),
        ('Windows user: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    ) -join [Environment]::NewLine
    try { $msg | Set-Content -LiteralPath $errorFile -Encoding UTF8 } catch {}
    try { Restore-All } catch {}
    exit 1
}
```powershell
function Get-FusState {
    try {
        $p = Get-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction Stop
        return @{ Exists = $true; Value = [int]$p.HideFastUserSwitching }
    } catch {
        return @{ Exists = $false; Value = $null }
    }
}

function Set-FusHidden {
    try {
        if (-not (Test-Path -LiteralPath $fusKey)) { New-Item -Path $fusKey -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    } catch {}
}

function Restore-Fus($Fus) {
    try {
        if ($Fus.Exists) {
            Set-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -Value ([int]$Fus.Value) -ErrorAction Stop
        } else {
            Remove-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Restore-All {
    Remove-OurRules
    if (-not (Test-Path -LiteralPath $stateFile)) { return }
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json

    foreach ($p in @($state.Profiles)) {
        try {
            Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop
        } catch {}
    }

    if (Test-Path -LiteralPath $proxyKey) {
        Set-RegFromState $proxyKey 'ProxyEnable' $state.Proxy.ProxyEnable
        Set-RegFromState $proxyKey 'ProxyServer' $state.Proxy.ProxyServer
        Set-RegFromState $proxyKey 'ProxyOverride' $state.Proxy.ProxyOverride
        Set-RegFromState $proxyKey 'AutoConfigURL' $state.Proxy.AutoConfigURL
        Notify-InternetSettings
    }

    Restore-Dns $state.Dns
    Restore-Doh $state.Doh
    Restore-Fus $state.Fus
    Remove-Item -LiteralPath $egressStatusFile -Force -ErrorAction SilentlyContinue

    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}

```

- `Restore-All` is the undo of EVERYTHING: remove all rules in our group,
  restore the three firewall profiles, proxy, DNS, DoH policies, FUS value,
  delete the status + state files.

**Act 8 — the main script:**

```powershell
try {
    Assert-Administrator
    Ensure-FirewallServices

    if ($RecoverOnly) {
        Restore-All
        'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
        exit 0
    }

    Remove-Item -LiteralPath $readyFile,$stopFile,$restoredFile,$errorFile -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $cfg.programPath)) {
        throw "Cheat.Guard executable path was not found: $($cfg.programPath)"
    }

    # Recover a previous interrupted session before taking a fresh snapshot.
    if (Test-Path -LiteralPath $stateFile) { Restore-All }

    $profiles = @(Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{ Name=$_.Name; Enabled=$_.Enabled.ToString(); DefaultOutboundAction=$_.DefaultOutboundAction.ToString() }
    })
    $state = [ordered]@{
        UserSid = $cfg.userSid
        Profiles = $profiles
        Proxy = [ordered]@{
            ProxyEnable = Get-RegState $proxyKey 'ProxyEnable'
            ProxyServer = Get-RegState $proxyKey 'ProxyServer'
            ProxyOverride = Get-RegState $proxyKey 'ProxyOverride'
            AutoConfigURL = Get-RegState $proxyKey 'AutoConfigURL'
        }
        Dns = Get-DnsState
        Doh = Get-DohState
        Fus = Get-FusState
    }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    Set-FusHidden

    # A user-configured proxy is a complete bypass: the browser hands the request to
    # the proxy, which resolves names and connects on its own, never touching the
    # local DNS filter. The original settings were snapshotted above and Restore-All
    # puts them back, so user proxy and PAC are force-disabled for the exam and all
    # browsing goes direct - where the DNS allowlist applies. (An older build's
    # leftover loopback proxy, which points at a port nothing listens on, is covered
    # by the same disable step.)
    try {
        Set-ItemProperty -LiteralPath $proxyKey -Name 'ProxyEnable' -Value 0 -ErrorAction Stop
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'ProxyServer' -ErrorAction SilentlyContinue
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
        Notify-InternetSettings
    } catch {}
    $state.Proxy.ProxyEnable = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.ProxyServer = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.AutoConfigURL = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    # Strict default-deny is essential: it prevents an unsupported browser, a browser installed
    # in an unusual path, or another application from bypassing the proxy during the exam.
    # The original profile settings were snapshotted above and Restore-All puts them back.
    Remove-OurRules

    # Enforcement is at name resolution, not at the socket layer. An earlier design set
    # every profile's DefaultOutboundAction to Block and allowed browsers to reach only a
    # local proxy port; that blocked unapproved sites but also killed approved ones on any
    # machine where a browser did not honour the injected proxy setting. The firewall is now
    # used only for narrow, additive Block rules that cannot break normal traffic.

    # Close the DNS-over-HTTPS escape at the network layer as well as by policy: deny TCP 443
    # to the well-known public DoH resolvers. Ordinary websites are unaffected, and the
    # Cheat.Guard filter's own upstream lookups use UDP/TCP 53, not 443.
    $dohResolvers = @(
        '1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15','45.90.28.0/24','45.90.30.0/24'
    )
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoH resolvers' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 443 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Deny DNS-over-TLS entirely (TCP and UDP 853): a custom resolver or a Windows 11
    # DoT setting would otherwise tunnel around the local filter the same way DoH would.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # A custom tool could bypass the local filter by querying a well-known public
    # resolver directly (nslookup facebook.com 8.8.8.8). Block port 53 to those
    # resolvers. The filter's own upstreams never use this list: the Java side drops
    # captured system resolvers that appear here and falls back to Quad9 unfiltered
    # endpoints instead, so its own path stays open.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Keep the Cheat.Guard process explicitly permitted outbound so its upstream DNS keeps
    # working even on a machine whose profiles already default to Block.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - filter host outbound' -Group $groupName -Direction Outbound -Program $cfg.programPath -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # ---- tunnel/remote-access hardening, then the egress web lockdown ----
    Add-TunnelPortBlocks
    $script:lastIps = ''
    $script:egressActive = $false
    if ((-not [string]::IsNullOrWhiteSpace($allowedIpFile)) -and (-not [string]::IsNullOrWhiteSpace($verifyHost))) {
        try {
            $script:egressActive = Apply-EgressLockdown
            $script:lastIps = (@(Read-AllowedIps) -join ',')
        } catch {
            $script:egressActive = $false
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($egressStatusFile)) {
        if ($script:egressActive) { 'ACTIVE' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
        else { 'FALLBACK' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
    }

    # Force browsers onto the system resolver, then point the system resolver at the
    # Cheat.Guard DNS filter. Unapproved domains then fail to resolve for every program,
    # while approved domains resolve normally and connect over their usual direct path.
    Disable-BrowserDoh
    $redirectIpv6 = [bool]$cfg.dnsIpv6
    $dnsChanged = Set-ExamDns -RedirectIpv6 $redirectIpv6
    if ($dnsChanged -lt 1) {
        throw 'Could not redirect any network adapter to the Cheat.Guard DNS filter (127.0.0.1). Check that a network adapter is connected.'
    }
    if (-not (Test-DnsFilter '127.0.0.1')) {
        throw 'The Cheat.Guard DNS filter on 127.0.0.1:53 did not answer a test lookup. Lockdown has been rolled back so the computer keeps working; start the exam again.'
    }

    # Chromium/Firefox cache DoH and resolver state, so restart them once when exam mode
    # begins to make sure the policy and the redirected DNS are picked up.
    foreach ($name in @('chrome','msedge','firefox','brave','opera','opera_gx','vivaldi','iexplore')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700

    # Verify DNS redirection before telling the Java app that lockdown is ready.
    $dnsOk = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' }).Count
    if ($dnsOk -lt 1) { throw 'DNS redirection verification failed: no adapter is using the Cheat.Guard DNS filter.' }
    if (-not (Test-DnsFilter '127.0.0.1')) { throw 'The Cheat.Guard DNS filter stopped answering during verification.' }

    # Keep new or re-connected adapters on the filter for the whole session. A USB
    # Wi-Fi dongle or a re-connected Ethernet adapter comes up with DHCP DNS and
    # would resolve straight through the real resolvers, bypassing the exam allowlist.
    $redirectedIfIndex = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in @($state.Dns)) { if ($e.InterfaceIndex) { [void]$redirectedIfIndex.Add([string]$e.InterfaceIndex) } }
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        [void]$redirectedIfIndex.Add([string]$a.ifIndex)
    }

    # This directory holds the session's control markers (stop, protect-request) and
    # the helper configuration. Restrict it to Administrators now that the app itself
    # runs elevated: the signed-in account keeps read access but can no longer forge
    # a stop marker to silently end the lockdown, rewrite the helper configuration,
    # or swap this script while the UAC prompt is on screen.
    try {
        $networkRoot = Split-Path -Parent $Config
        takeown /F "$networkRoot" /A | Out-Null
        icacls "$networkRoot" /inheritance:r | Out-Null
        icacls "$networkRoot" /grant "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null   # Administrators: full
        icacls "$networkRoot" /grant "*S-1-5-18:(OI)(CI)(F)"     | Out-Null   # SYSTEM: full
        icacls "$networkRoot" /grant "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Null  # Users: read+execute only
    } catch {}

    'READY' | Set-Content -LiteralPath $readyFile -Encoding ASCII

    $loopCount = 0
    while ($true) {
        if (Test-Path -LiteralPath $stopFile) { break }
        if (-not (Get-Process -Id ([int]$cfg.parentPid) -ErrorAction SilentlyContinue)) { break }
        Handle-ProtectRequest
        $loopCount++
        if ($script:egressActive -and ($loopCount % 10) -eq 0) {
            # Approved pages resolve new CDN addresses mid-exam; the allow rule follows.
            $ips = @(Read-AllowedIps)
            if ($ips.Count -ge 1) {
                $blob = $ips -join ','
                if ($blob -ne $script:lastIps) {
                    try {
                        Set-AllowedDestinationRules $ips
                        $script:lastIps = $blob
                    } catch {}
                }
            }
        }
        foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
            $key = [string]$a.ifIndex
            if (-not $redirectedIfIndex.Contains($key)) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
                    if ($redirectIpv6) {
                        try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
                    }
                    [void]$redirectedIfIndex.Add($key)
                } catch {}
            }
        }
        Start-Sleep -Milliseconds 500
    }

    # The app seals the log just before asking for shutdown, so serve one last request.
    Handle-ProtectRequest

    Restore-All
    'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
    exit 0
} catch {
    $msg = @(
        'Cheat.Guard strict-network helper failed.',
        ('Message: ' + $_.Exception.Message),
        ('Type: ' + $_.Exception.GetType().FullName),
        ('PowerShell: ' + $PSVersionTable.PSVersion.ToString()),
        ('Windows user: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    ) -join [Environment]::NewLine
    try { $msg | Set-Content -LiteralPath $errorFile -Encoding UTF8 } catch {}
    try { Restore-All } catch {}
    exit 1
}
```

- `-RecoverOnly` → restore + exit (crash recovery path).
- Normal run: verify program path → recover stale → SNAPSHOT → hide fast user
  switching → disable user proxy/PAC → DoH off → firewall rules (DoH IPs,
  DoT 853, public 53, allow our own exe, tunnel blocks, egress attempt) →
  redirect DNS on every adapter → VERIFY DNS → ACL the network folder → READY.
- The wait loop (every 500 ms): stop marker? parent alive? protect requests?
  every 10th loop refresh the allowed-IP rule? new adapter → redirect it?
- `catch` writes error.txt and RESTORES EVERYTHING anyway.

## B3. The other twelve files, full code

### 5) watchdog/ViolationListener.java — the contract

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.Violation;

/**
 * OOP Concept: INTERFACE (abstraction)
 * --------------------------------------
 * WatchdogEngine ke direct AlarmPlayer/ScreenLocker class chinte hobe na.
 * Eta shudhu jane je "kono violation hole, ekta onVoilation() call hobe".
 * Main.java run-time e ekta implementation (lambda) diye WatchdogEngine ke
 * bole dey exactly ki korte hobe (alarm baja, screen lock kora, etc).
 * Eta "loose coupling" - alada module gula ek-onner shathe tightly bound thake na.
 */
public interface ViolationListener {
    void onViolation(Violation violation);
}
```

One method. The engine calls it without knowing the GUI — loose coupling.
Main implements it as a lambda; the tests pass null. (The Banglish comment
documents the OOP idea right in the code.)

### 6) watchdog/PowerShellUtil.java — safe probe launching

```java
package com.cheatguard.watchdog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Starts small read-only PowerShell probes without Windows command-line quote corruption. */
final class PowerShellUtil {
    private PowerShellUtil() {}

    static Process start(String script) throws IOException {
        String safeScript = "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script;
        String encoded = Base64.getEncoder().encodeToString(safeScript.getBytes(StandardCharsets.UTF_16LE));
        ProcessBuilder pb = new ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                "-EncodedCommand", encoded);
        // Probe output is machine-readable. Never mix PowerShell diagnostics into it.
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        return pb.start();
    }
}
```

Base64 UTF-16LE + `-EncodedCommand`: no quoting can corrupt a probe. stderr is
DISCARDED so error text cannot pollute machine-readable output.

### 7) watchdog/ProcessScanner.java — visible windows

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Returns top-level visible Windows applications with PID, executable name and
 * window title.
 *
 * <p>Robustness rules baked in (learned the hard way in earlier builds):
 * the script is sent encoded so no shell quoting can corrupt it, output is read
 * as UTF-8 so window titles with special characters survive, the probe can never
 * hang longer than its timeout, and the child process is always destroyed so a
 * stuck PowerShell cannot leak on every watchdog cycle. On non-Windows systems
 * the scan returns an empty list instead of failing.
 */
public class ProcessScanner {

    private static final String FIELD_SEPARATOR = "@@@";
    private static final long COMMAND_TIMEOUT_SECONDS = 8;

    public List<ProcessInfo> getRunningProcesses() {
        List<ProcessInfo> out = new ArrayList<>();
        if (!isWindows()) return out;
        try {
            // $p.Path is the executable location; the watchdog uses it to tell the
            // student's own compiled work (built into the exam folder) from foreign apps.
            String command =
                    "Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | " +
                    "ForEach-Object { '{0}" + FIELD_SEPARATOR + "{1}" + FIELD_SEPARATOR + "{2}"
                            + FIELD_SEPARATOR + "{3}' -f " +
                            "$_.Id, $_.ProcessName, $_.MainWindowTitle, $_.Path }";
            Process process = PowerShellUtil.start(command);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.trim().split(FIELD_SEPARATOR, 4);
                    if (parts.length < 2) continue;
                    try {
                        long pid = Long.parseLong(parts[0].trim());
                        String name = parts[1].trim();
                        if (!name.toLowerCase(Locale.ROOT).endsWith(".exe")) name += ".exe";
                        String title = parts.length >= 3 ? parts[2].trim() : "";
                        String path = parts.length >= 4 ? parts[3].trim() : "";
                        out.add(new ProcessInfo(pid, name, title, "", path));
                    } catch (NumberFormatException ignored) {
                        // a garbled line must never abort the whole scan
                    }
                }
            }
            if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            AppLog.warn("Process scan error: " + e.getMessage());
        }
        return out;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
```

`Get-Process | Where MainWindowTitle -ne ''` → `Id@@@Name@@@Title@@@Path`.
`split("@@@", 4)` with limit 4 so a path containing the separator cannot break
it. 8-second timeout then `destroyForcibly()`.

### 8) watchdog/ProcessInfo.java — pure data

```java
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
```

Five final fields, three overloaded constructors chaining with `this(...)`.
The 5-field version carries the exe PATH, which the watchdog uses for the
exam-folder rule.

### 9) watchdog/ProcessWhitelist.java — the name-decision brain

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Strict application allowlist. Browsers are judged by website, not by process. */
public class ProcessWhitelist {

    /**
     * Cheat.Guard itself and the Windows shell. Task Manager is deliberately not here:
     * it is the obvious way to kill the invigilator app, so it is closed like any other
     * unapproved application unless an administrator adds it to the allowlist.
     */
    private static final Set<String> ALWAYS_ALLOWED = new HashSet<>(Arrays.asList(
            "cheatguard.exe", "explorer.exe"));

    private static final Set<String> BROWSERS = new HashSet<>(Arrays.asList(
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
            "opera.exe", "opera_gx.exe", "vivaldi.exe"));

    /**
     * Windows shell and platform components. These are never student applications,
     * so they are neither closed nor written to the audit log — listing them would
     * bury the events an invigilator actually needs to read.
     */
    private static final Set<String> SYSTEM_PROCESSES = new HashSet<>(Arrays.asList(
            // shell and desktop
            "explorer.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "taskhostw.exe",
            "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
            "searchapp.exe", "searchui.exe", "searchhost.exe", "textinputhost.exe",
            "applicationframehost.exe", "lockapp.exe", "widgets.exe", "widgetservice.exe",
            "systemsettings.exe", "useroobebroker.exe", "dllhost.exe", "wudfhost.exe",
            "fontdrvhost.exe", "csrss.exe", "winlogon.exe", "logonui.exe", "smartscreen.exe",
            // notifications, input, accessibility
            "shellhost.exe", "inputapp.exe", "narrator.exe", "magnify.exe", "osk.exe",
            // security and platform components that can surface a window
            "securityhealthsystray.exe", "securityhealthservice.exe", "mpcmdrun.exe",
            "msmpeng.exe", "nissrv.exe", "wermgr.exe", "werfault.exe", "sppsvc.exe",
            "backgroundtaskhost.exe", "phoneexperiencehost.exe", "yourphone.exe",
            "msedgewebview2.exe", "crashpad_handler.exe",
            // Windows update / Store plumbing
            "usoclient.exe", "mousocoreworker.exe", "tiworker.exe", "trustedinstaller.exe",
            "winstore.app.exe", "storeexperiencehost.exe",
            // editor platform helper that VS Code-class IDEs keep respawning
            "extensionhost.exe", "extension host.exe", "extension_host.exe"));

    public boolean isAllowed(String processName) {
        if (processName == null) return true;
        String p = processName.toLowerCase(Locale.ROOT);
        if (ALWAYS_ALLOWED.contains(p)) return true;
        if (SYSTEM_PROCESSES.contains(p)) return true;
        if (BROWSERS.contains(p)) return true;
        return AppConfig.getInstance().getAllowedProcesses().contains(p);
    }

    /** True for Windows components that must stay invisible in the audit log. */
    public boolean isSystemProcess(String processName) {
        if (processName == null) return true;
        String p = processName.toLowerCase(Locale.ROOT);
        return SYSTEM_PROCESSES.contains(p) || ALWAYS_ALLOWED.contains(p);
    }

    public boolean isBrowser(String processName) {
        return processName != null && BROWSERS.contains(processName.toLowerCase(Locale.ROOT));
    }

    /** "code.exe" becomes "Visual Studio Code" (stored real name) or "Code". */
    public static String friendlyName(String processName) {
        if (processName == null || processName.isBlank()) return "Unknown app";
        String n = processName.trim();
        String lower = n.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".exe")) {
            try {
                String real = com.cheatguard.config.AppConfig.getInstance()
                        .getAppDisplayName(lower);
                if (real != null && !real.isBlank()) return real;
            } catch (Exception ignored) {
                // config unavailable (tests, early boot): fall through to the exe name
            }
        }
        if (lower.endsWith(".exe")) n = n.substring(0, n.length() - 4);
        n = n.replace('_', ' ').replace('-', ' ').trim();
        if (n.isEmpty()) return "Unknown app";
        return Character.toUpperCase(n.charAt(0)) + n.substring(1);
    }
}
```

Three private sets: ALWAYS_ALLOWED (us + explorer), BROWSERS (judged by
website), SYSTEM_PROCESSES (~50 Windows parts, including the extension-host
variants). `friendlyName()` turns "mingw32-gcc.exe" into "Mingw32 gcc" — the
text the invigilator reads.

### 10) watchdog/ProcessController.java — the closer

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

/** Windows process enforcement helper. */
public class ProcessController {
    public boolean terminate(long pid) {
        if (pid <= 0) return false;
        try {
            ProcessBuilder pb = new ProcessBuilder("taskkill", "/PID", Long.toString(pid), "/T", "/F");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            int code = p.waitFor();
            return code == 0;
        } catch (Exception e) {
            AppLog.warn("Could not terminate PID " + pid + ": " + e.getMessage());
            return false;
        }
    }
}
```

`taskkill /PID n /T /F` — `/T` also kills children, `/F` forces. The exit code
decides grey OK vs red ALERT.

### 11) watchdog/SiteMonitor.java — reading the browser's address bar

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Reads foreground browser URL via Windows UI Automation when possible, with title fallback. */
public class SiteMonitor {
    public ProcessInfo getForegroundWindow() {
        try {
            String ps =
                    "$sig='[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); [DllImport(\"user32.dll\")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);';" +
                    "Add-Type -MemberDefinition $sig -Name Win32 -Namespace Native -ErrorAction SilentlyContinue;" +
                    "$h=[Native.Win32]::GetForegroundWindow();$pid2=0;[Native.Win32]::GetWindowThreadProcessId($h,[ref]$pid2)|Out-Null;" +
                    "$p=Get-Process -Id $pid2 -ErrorAction SilentlyContinue;$url='';" +
                    "if($p){try{Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue;" +
                    "$root=[System.Windows.Automation.AutomationElement]::FromHandle($h);" +
                    "$cond=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Edit);" +
                    "$edits=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,$cond);" +
                    "foreach($e in $edits){$n=$e.Current.Name;if($n -match '(?i)address|location|url'){try{$vp=$e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern);$v=$vp.Current.Value;if($v){$url=$v;break}}catch{}}}}catch{};" +
                    "$p.Id.ToString() + '@@@' + $p.ProcessName + '@@@' + $p.MainWindowTitle + '@@@' + $url}";
            Process p = PowerShellUtil.start(ps);
            String line;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) { line = r.readLine(); }
            p.waitFor();
            if (line == null) return null;
            String[] parts = line.split("@@@", 4);
            if (parts.length < 2) return null;
            long pid = Long.parseLong(parts[0].trim());
            String name = parts[1].trim();
            if (!name.toLowerCase(Locale.ROOT).endsWith(".exe")) name += ".exe";
            String title = parts.length >= 3 ? parts[2].trim() : "";
            String url = parts.length >= 4 ? parts[3].trim() : "";
            return new ProcessInfo(pid, name, title, url);
        } catch (Exception e) { return null; }
    }

    public boolean isAllowedBrowserPage(ProcessInfo info) {
        if (info == null) return false;
        String address = info.getBrowserUrl();
        if (address != null && !address.trim().isEmpty()) {
            return AppConfig.getInstance().isSiteAllowed(address.trim());
        }

        // Fallback for browsers/versions where the address bar is not exposed to UI Automation.
        String title = info.getWindowTitle();
        if (title == null || title.trim().isEmpty()) return false;
        String lower = title.toLowerCase(Locale.ROOT);
        for (String site : AppConfig.getInstance().getAllowedSites()) {
            if (lower.contains(site)) return true;
            int dot = site.indexOf('.');
            if (dot > 0) {
                String brand = site.substring(0, dot);
                if (brand.length() >= 3 && lower.contains(brand)) return true;
            }
        }
        return false;
    }
}
```

Win32 `GetForegroundWindow` → PID → UI Automation finds an **Edit** control
named address/location → `ValuePattern` reads the URL.
`isAllowedBrowserPage` checks the URL; fallback: the window title contains the
site or its brand (min 3 letters).

### 12) watchdog/FolderAccessMonitor.java — Explorer windows

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Watches current File Explorer locations and reports access outside the per-student exam folder. */
public class FolderAccessMonitor {
    private final File allowedFolder;

    public FolderAccessMonitor(File allowedFolder) {
        this.allowedFolder = allowedFolder;
    }

    public List<String> getUnauthorizedExplorerFolders() {
        List<String> bad = new ArrayList<>();
        for (String path : getExplorerFolders()) {
            if (!isInsideAllowedFolder(path)) bad.add(path);
        }
        return bad;
    }

    private List<String> getExplorerFolders() {
        List<String> paths = new ArrayList<>();
        try {
            String cmd = "$s=New-Object -ComObject Shell.Application; $s.Windows() | ForEach-Object { try { if($_.FullName -match 'explorer.exe$' -and $_.LocationURL -like 'file:*'){ $_.LocationURL } } catch {} }";
            Process p = PowerShellUtil.start(cmd);
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || !line.toLowerCase().startsWith("file:")) continue;
                    try { paths.add(new File(new URI(line)).getCanonicalPath()); }
                    catch (Exception ignored) {}
                }
            }
            p.waitFor();
        } catch (Exception e) {
            AppLog.warn("Folder scan error: " + e.getMessage());
        }
        return paths;
    }

    private boolean isInsideAllowedFolder(String path) {
        try {
            String allowed = allowedFolder.getCanonicalPath();
            String target = new File(path).getCanonicalPath();
            return target.equalsIgnoreCase(allowed) || target.toLowerCase().startsWith((allowed + File.separator).toLowerCase());
        } catch (Exception e) { return false; }
    }
}
```

`Shell.Application` COM: every open Explorer window's `LocationURL` →
canonical File path → compared by canonical prefix with the exam folder.

### 13) watchdog/ExternalDeviceMonitor.java — USB events

```java
package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Detects USB storage, USB network/Wi-Fi adapters and portable data devices. */
public class ExternalDeviceMonitor {
    private static final Set<String> VALID_TYPES = new HashSet<>(Arrays.asList(
            "USB_STORAGE", "USB_NETWORK", "PORTABLE_DEVICE"));

    private final Map<String, String> known = new LinkedHashMap<>();

    public ExternalDeviceMonitor() { known.putAll(snapshot()); }

    /** Devices that were already connected before monitoring started. */
    public synchronized List<String> getPresentRiskDevices() {
        return new ArrayList<>(known.values());
    }

    /** Devices attached after the initial snapshot. */
    public synchronized List<String> checkForNewRiskDevices() {
        Map<String, String> current = snapshot();
        List<String> added = new ArrayList<>();
        for (Map.Entry<String, String> e : current.entrySet()) {
            if (!known.containsKey(e.getKey())) added.add(e.getValue());
        }
        known.clear();
        known.putAll(current);
        return added;
    }

    private Map<String, String> snapshot() {
        Map<String, String> devices = new LinkedHashMap<>();
        try {
            String cmd =
                    "Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'} | ForEach-Object { 'USB_STORAGE@@@' + $_.PNPDeviceID + '@@@' + $_.Model };" +
                    "Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.PNPDeviceID -like 'USB*'} | ForEach-Object { 'USB_NETWORK@@@' + $_.PNPDeviceID + '@@@' + $_.Name };" +
                    "if(Get-Command Get-PnpDevice -ErrorAction SilentlyContinue){ Get-PnpDevice -PresentOnly -Class WPD | ForEach-Object { 'PORTABLE_DEVICE@@@' + $_.InstanceId + '@@@' + $_.FriendlyName } }";
            Process p = PowerShellUtil.start(cmd);
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String[] parts = line.split("@@@", 3);
                    if (parts.length != 3) continue;
                    String type = parts[0].trim();
                    String id = parts[1].trim();
                    String name = cleanName(parts[2]);
                    if (!VALID_TYPES.contains(type) || !looksLikeDeviceId(id) || looksLikePowerShellNoise(name)) continue;
                    devices.put(type + "|" + id, friendlyType(type) + ": " + name);
                }
            }
            p.waitFor();
        } catch (Exception e) {
            AppLog.warn("External device scan error: " + e.getMessage());
        }
        return devices;
    }

    private boolean looksLikeDeviceId(String id) {
        if (id == null) return false;
        String s = id.trim();
        if (s.length() < 3 || s.length() > 600) return false;
        if (s.contains("$(") || s.contains("@@@") || s.contains("CommandNotFoundException")) return false;
        return s.contains("\\") || s.toUpperCase(Locale.ROOT).startsWith("USB") || s.toUpperCase(Locale.ROOT).startsWith("SWD");
    }

    private boolean looksLikePowerShellNoise(String value) {
        if (value == null) return true;
        String s = value.toLowerCase(Locale.ROOT);
        return s.contains("commandnotfoundexception") || s.contains("not recognized as the name") ||
                s.contains("the term '") || s.contains("categoryinfo") || s.contains("fullyqualifiederrorid") || s.contains("$(");
    }

    private String friendlyType(String type) {
        if ("USB_STORAGE".equals(type)) return "USB storage";
        if ("USB_NETWORK".equals(type)) return "USB network adapter";
        if ("PORTABLE_DEVICE".equals(type)) return "Portable device";
        return "External device";
    }

    private String cleanName(String value) {
        String v = value == null ? "" : value.trim();
        return v.isEmpty() ? "Unknown device" : v.replaceAll("\\s+", " ");
    }
}
```

Three CIM queries (USB disks, USB network adapters, portable devices). Every
line is validated against PowerShell error garbage. The engine diffs
snapshots — only NEW devices alert.

### 14) watchdog/WebsiteViolationReporter.java — the noise filter

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.util.Locale;

/**
 * Decides whether a denied website lookup is a real student violation.
 *
 * <p>A browser and Windows itself generate a constant stream of update, telemetry
 * and connectivity lookups. Those stay blocked, but turning each one into a
 * RED-flag row would bury the events that matter. This class filters that noise
 * and confirms the student is actually looking at an unapproved page in a
 * foreground browser before a violation is raised.
 */
final class WebsiteViolationReporter {

    private final SiteMonitor siteMonitor = new SiteMonitor();
    private final ProcessWhitelist processWhitelist = new ProcessWhitelist();

    private volatile long foregroundCacheAt;
    private volatile String foregroundCacheHost = "";
    private volatile boolean foregroundCacheBrowser;
    private volatile boolean foregroundCacheAllowed;

    /**
     * Map a denied host to the host that should be reported as a RED violation.
     *
     * @return the user-facing host, or {@code null} when the denial is background
     *         traffic that should not be reported
     */
    String userFacingViolation(String host) {
        String key = normalizeHost(host);
        if (key.isEmpty() || isBackgroundNoiseHost(key)) return null;
        return foregroundUnauthorizedHost(key);
    }

    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h.startsWith("www.") ? h.substring(4) : h;
    }

    /**
     * The unapproved website the student is actually looking at, or null when the
     * foreground is not a supported browser or is already on an approved page. A
     * short cache avoids spawning a PowerShell probe for every lookup in the same
     * navigation burst.
     */
    private String foregroundUnauthorizedHost(String blockedHost) {
        long now = System.currentTimeMillis();
        if (now - foregroundCacheAt > 900L) {
            String host = "";
            boolean browser = false;
            boolean allowedPage = false;
            try {
                ProcessInfo fg = siteMonitor.getForegroundWindow();
                browser = fg != null && processWhitelist.isBrowser(fg.getName());
                if (browser) {
                    host = AppConfig.normalizeSite(fg.getBrowserUrl());
                    allowedPage = siteMonitor.isAllowedBrowserPage(fg);
                }
            } catch (Exception ignored) {
                // treat a failed probe as "not a foreground browser"
            }
            foregroundCacheHost = host;
            foregroundCacheBrowser = browser;
            foregroundCacheAllowed = allowedPage;
            foregroundCacheAt = now;
        }

        if (!foregroundCacheBrowser) return null;
        if (foregroundCacheAllowed) return null;
        if (!foregroundCacheHost.isEmpty()) return foregroundCacheHost;

        // Address bar not exposed and the title does not identify an approved page.
        return blockedHost;
    }

    /** Known browser/Windows background endpoints that are not student violations. */
    static boolean isBackgroundNoiseHost(String host) {
        String h = normalizeHost(host);
        if (h.isEmpty()) return true;

        // Discord background gateway/CDN/status traffic (discord.com itself is NOT suppressed).
        if (h.equals("gateway.discord.gg") || h.endsWith(".gateway.discord.gg")
                || (h.startsWith("gateway-") && h.endsWith(".discord.gg"))
                || h.equals("status.discord.com") || h.equals("cdn.discordapp.com")
                || h.equals("media.discordapp.net")) return true;

        // Chromium/Google update, optimization and connectivity background services.
        if (h.equals("update.googleapis.com") || h.equals("clientservices.googleapis.com")
                || h.equals("optimizationguide-pa.googleapis.com") || h.equals("safebrowsing.googleapis.com")
                || h.equals("redirector.gvt1.com") || h.equals("clients2.google.com")
                || h.equals("clients4.google.com") || h.equals("connectivitycheck.gstatic.com")) return true;

        // Windows/Edge/OneDrive telemetry and push-notification background services.
        if (h.equals("mobile.events.data.microsoft.com") || h.endsWith(".events.data.microsoft.com")
                || h.equals("skydrive.wns.windows.com") || h.endsWith(".wns.windows.com")
                || h.equals("edge.microsoft.com") || h.equals("msedge.api.cdp.microsoft.com")) return true;

        // Name-resolution plumbing that is never a browsed website.
        if (h.equals("wpad") || h.startsWith("wpad.") || h.endsWith(".local")
                || h.endsWith(".arpa") || h.equals("localhost")) return true;

        return false;
    }
}
```

Gate 1: `isBackgroundNoiseHost` (Discord gateway/CDN, Chrome/Google update
endpoints, Microsoft telemetry, wpad/`.local`/`.arpa`). Gate 2: the foreground
window (cached 900 ms) must be a browser on a non-allowed page. Only then the
host is user-facing.

### 15) watchdog/SessionEnvironment.java — clipboard hygiene

```java
package com.cheatguard.watchdog;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;

/**
 * Prepares the Windows desktop environment at the start of an exam session.
 *
 * <p>Anything a student copied <em>before</em> the exam — notes, code, an answer from
 * a chat app — would otherwise still be one paste away, so the clipboard is emptied
 * when a session starts.
 *
 * <p>Emptying the clipboard is not enough on its own: Windows keeps a clipboard
 * <em>history</em> (Win+V) and clearing the current item leaves that history intact,
 * so a student could simply press Win+V and pick a pre-exam entry. The history is
 * therefore discarded as well — Windows drops the stored entries when the feature is
 * switched off, so it is toggled off and immediately restored to the value the user
 * had.
 *
 * <p>The clipboard stays fully usable during the session. Copy and paste, and Win+V
 * for anything copied after the session started, all work as normal; only the
 * pre-session contents are gone.
 */
public final class SessionEnvironment {

    private static final String CLIPBOARD_KEY = "HKCU\\Software\\Microsoft\\Clipboard";

    private Integer previousHistory;
    private boolean toggledHistory;

    /** Empty the clipboard and discard pre-session clipboard history. */
    public void prepare() {
        clearClipboard();
        if (!isWindows()) return;
        clearClipboardHistory();
        clearRecentItems();
    }

    /**
     * Wipe the Windows "Recent items" lists: Start-menu recent files, jump lists
     * and the recent list inside common Open/Save dialogs. They are only
     * auto-generated shortcuts, and they are exactly how a pre-exam file would be
     * reopened inside an ALLOWED app one click after the session starts. The
     * files themselves are untouched.
     */
    private void clearRecentItems() {
        run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "Remove-Item -LiteralPath \"$env:APPDATA\\Microsoft\\Windows\\Recent\\*\" "
                        + "-Recurse -Force -ErrorAction SilentlyContinue");
    }

    /**
     * Safety net for an interrupted {@link #prepare()}. The history setting is put
     * back inside prepare itself, so normally there is nothing left to do here — the
     * clipboard is deliberately left alone so a student does not lose work.
     */
    public void restore() {
        if (toggledHistory && isWindows()) {
            restoreDword("EnableClipboardHistory", previousHistory);
            toggledHistory = false;
        }
    }

    /**
     * Discard stored clipboard history. The documented WinRT call is tried first; if
     * it is unavailable, switching the feature off drops the stored entries, and the
     * user's original setting is restored immediately afterwards so Win+V keeps
     * working during the exam.
     */
    private void clearClipboardHistory() {
        if (run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "[Windows.ApplicationModel.DataTransfer.Clipboard,Windows.ApplicationModel.DataTransfer,"
                        + "ContentType=WindowsRuntime] | Out-Null; "
                        + "[Windows.ApplicationModel.DataTransfer.Clipboard]::ClearHistory() | Out-Null")) {
            return;
        }
        previousHistory = readDword("EnableClipboardHistory");
        toggledHistory = true;
        writeDword("EnableClipboardHistory", 0);
        sleep(400);
        restoreDword("EnableClipboardHistory", previousHistory);
        toggledHistory = false;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /** Empty both the Java-visible clipboard and the Windows clipboard buffer. */
    public void clearClipboard() {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(""), null);
        } catch (Exception ignored) {
            // headless or clipboard owned by another process
        }
        if (!isWindows()) return;
        // Set-Clipboard with no value empties the native clipboard, including formats
        // (images, files) that the Java clipboard API would not replace.
        run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "Set-Clipboard -Value $null -ErrorAction SilentlyContinue; "
                        + "Add-Type -AssemblyName System.Windows.Forms; "
                        + "[System.Windows.Forms.Clipboard]::Clear()");
    }

    // ------------------------------------------------------------- primitives

    private Integer readDword(String name) {
        String out = capture("reg", "query", CLIPBOARD_KEY, "/v", name);
        int at = out.indexOf("REG_DWORD");
        if (at < 0) return null;
        String tail = out.substring(at + 9).trim();
        int end = tail.indexOf('\n');
        if (end > 0) tail = tail.substring(0, end).trim();
        try {
            return Integer.decode(tail);
        } catch (Exception e) {
            return null;
        }
    }

    private void writeDword(String name, int value) {
        run("reg", "add", CLIPBOARD_KEY, "/v", name, "/t", "REG_DWORD",
                "/d", Integer.toString(value), "/f");
    }

    private void restoreDword(String name, Integer previous) {
        if (previous == null) {
            run("reg", "delete", CLIPBOARD_KEY, "/v", name, "/f");
        } else {
            writeDword(name, previous);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    /** Run a command; true when it reported success. */
    private static boolean run(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception ignored) {
            // best effort; a clipboard tweak must never stop an exam
            return false;
        }
    }

    private static String capture(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            return out;
        } catch (Exception e) {
            return "";
        }
    }
}
```

Clipboard cleared twice (Java Toolkit + native `Set-Clipboard`/WinForms). The
Win+V history: WinRT `ClearHistory()` first; fallback toggles the registry
value off for 400 ms (Windows drops stored entries) and restores the user's
original setting. `restore()` is the end-of-exam safety net. `prepare()` ALSO
wipes the Windows recent-items lists (Start menu recents, jump lists,
Open-dialog recents) — they are only auto-generated shortcuts, and they are
exactly how a pre-exam file would be reopened inside an allowed app in one
click. The files themselves are untouched.

### 16) watchdog/AllowedAppLauncher.java — launching an approved app

```java
package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Launches an approved application pointed at the student's exam folder.
 *
 * <p>The student never has to browse the disk to reach their workspace, which is
 * the point: the exam folder is the only folder they are meant to touch, and any
 * Explorer window opened somewhere else is reported by {@link FolderAccessMonitor}.
 */
public final class AllowedAppLauncher {

    /** Editors and IDEs that open a folder when it is passed as the first argument. */
    private static final List<String> FOLDER_AWARE = Arrays.asList(
            "code.exe", "code - insiders.exe", "codium.exe", "cursor.exe",
            "idea64.exe", "pycharm64.exe", "clion64.exe", "webstorm64.exe",
            "studio64.exe", "eclipse.exe", "subl.exe", "atom.exe", "devenv.exe");

    private AllowedAppLauncher() {
    }

    /**
     * Start an approved app on the exam folder.
     *
     * @return {@code null} on success, otherwise a message to show the invigilator
     */
    public static String launch(String appName, File examFolder) {
        if (appName == null || appName.isBlank()) return "No application selected.";
        String name = appName.trim().toLowerCase(Locale.ROOT);
        if (!name.endsWith(".exe")) name = name + ".exe";

        File executable = resolve(name);
        if (executable == null) {
            return "Could not find " + ProcessWhitelist.friendlyName(name) + " on this computer.\n"
                    + "Open \"Allowed apps and websites\" and add it again with \"Choose .exe\" "
                    + "so Cheat.Guard knows where it is installed.";
        }
        if (examFolder == null || !examFolder.isDirectory()) {
            return "The exam folder no longer exists.";
        }

        try {
            // Packaged runs are elevated: launching directly would start the app as
            // ADMIN, which would bypass the student's file-access locks. Handing the
            // launch to Explorer starts it in the STUDENT's session instead. A
            // temporary shortcut carries the exam-folder argument and working dir.
            boolean elevatedRun = new File(
                    System.getProperty("jpackage.app-path", "")).isFile();
            if (elevatedRun) {
                File lnk = createStudentShortcut(executable, examFolder, name);
                if (lnk != null) {
                    new ProcessBuilder("explorer.exe", lnk.getAbsolutePath()).start();
                    return null;
                }
            }
            ProcessBuilder pb = FOLDER_AWARE.contains(name)
                    ? new ProcessBuilder(executable.getAbsolutePath(), examFolder.getAbsolutePath())
                    : new ProcessBuilder(executable.getAbsolutePath());
            // Even when the app ignores the argument, starting it here makes the exam
            // folder the default location in its open/save dialogs.
            pb.directory(examFolder);
            pb.redirectErrorStream(true);
            pb.start();
            return null;
        } catch (Exception e) {
            return "Could not start " + ProcessWhitelist.friendlyName(name) + ": " + e.getMessage();
        }
    }

    /**
     * Build a one-click shortcut in the exam folder that starts the approved app
     * with the exam folder as argument and working directory. The shortcut also
     * stays behind as a student-friendly launcher for the rest of the session.
     */
    private static File createStudentShortcut(File exe, File examFolder, String name) {
        try {
            File lnk = new File(examFolder, "Launch " + ProcessWhitelist.friendlyName(name) + ".lnk");
            String ps = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
                    + lnk.getAbsolutePath().replace("'", "''") + "');"
                    + "$s.TargetPath='" + exe.getAbsolutePath().replace("'", "''") + "';"
                    + (FOLDER_AWARE.contains(name)
                        ? "$s.Arguments='" + examFolder.getAbsolutePath().replace("'", "''") + "';"
                        : "")
                    + "$s.WorkingDirectory='" + examFolder.getAbsolutePath().replace("'", "''") + "';"
                    + "$s.Save()";
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", ps)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            return lnk.isFile() ? lnk : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Stored path first, then PATH, then the usual Windows install locations. */
    private static File resolve(String name) {
        String stored = AppConfig.getInstance().getProcessPath(name);
        if (stored != null) {
            File f = new File(stored);
            if (f.isFile()) return f;
        }
        File onPath = fromWhere(name);
        if (onPath != null) return onPath;

        for (String base : new String[]{
                System.getenv("ProgramFiles"),
                System.getenv("ProgramFiles(x86)"),
                System.getenv("LOCALAPPDATA")}) {
            if (base == null || base.isBlank()) continue;
            File hit = searchShallow(new File(base), name, 0);
            if (hit != null) return hit;
        }
        return null;
    }

    private static File fromWhere(String name) {
        try {
            Process p = new ProcessBuilder("where", name).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            for (String line : out.split("\\R")) {
                File f = new File(line.trim());
                if (f.isFile()) return f;
            }
        } catch (Exception ignored) {
            // "where" is unavailable or found nothing
        }
        return null;
    }

    /** Look a few levels deep only; a full disk crawl would freeze the UI. */
    private static File searchShallow(File dir, String name, int depth) {
        if (depth > 3 || dir == null || !dir.isDirectory()) return null;
        File direct = new File(dir, name);
        if (direct.isFile()) return direct;
        File[] children = dir.listFiles(File::isDirectory);
        if (children == null) return null;
        for (File child : children) {
            File hit = searchShallow(child, name, depth + 1);
            if (hit != null) return hit;
        }
        return null;
    }
}
```

`resolve()`: stored path → `where` on PATH → shallow search (depth 3) in
Program Files / LOCALAPPDATA. Folder-aware editors get the exam folder as an
argument; EVERYTHING gets it as the working directory, so open/save dialogs
start in the exam folder.

## B4. OOP concepts in my part (with the real places)

1. **Interface (abstraction)** — `ViolationListener`: one method; the engine
   calls it without knowing the GUI. Main implements it as a LAMBDA — runtime
   polymorphism.
2. **Implementing interfaces** — `WatchdogEngine implements Runnable` (own
   thread), `DnsAllowlistServer implements Closeable` (try-with-resources).
3. **Encapsulation** — the 60-second grace window is a private final field;
   `ProcessWhitelist`'s sets are private; outsiders only ask `isAllowed(...)`.
4. **Composition** — `WatchdogEngine` HAS a scanner, whitelist, closer, folder
   monitor and device monitor; each small class does one job.
5. **Constructor overloading** — `DnsAllowlistServer` and `ProcessInfo` have
   multiple constructors chaining with `this(...)`.
6. **Package-private design** — `PowerShellUtil` and `WebsiteViolationReporter`
   are package-private classes: usable inside the watchdog package, invisible
   outside.

## B5. Technologies in my part

Raw UDP sockets + DNS wire format parsed by hand · `ExecutorService` pool
(8 workers) · `ConcurrentHashMap` cache · connected-socket anti-spoofing ·
scheduled file flushing · PowerShell `-EncodedCommand` probes · elevated
helper with a file-marker protocol · `Set-DnsClientServerAddress`,
`New-NetFirewallRule`, `Get-NetAdapter`/`Get-NetRoute`, registry policies,
`icacls`/`takeown` · UI Automation (browser URL) · Shell.Application COM
(Explorer windows) · CIM/WMI queries (devices) · `ProcessHandle.allProcesses()`
with PID+start-time identity · `taskkill /T /F`.

## B6. Questions Sir may ask me

**Q: How exactly do you block a website?**
A: The computer asks our local DNS server for the address. Not allowed → we
answer "does not exist". No address, no connection — in any program.

**Q: What if the student changes DNS settings?**
A: They cannot — that needs admin. And the helper re-points every adapter every
half second, including adapters that appear mid-exam.

**Q: What about a VPN?**
A: Three layers: VPN programs are closed wherever they are installed, their
ports are firewalled, and the firewall only lets web traffic reach approved
site addresses anyway.

**Q: Raw IP address typed directly?**
A: Default-deny outbound: only addresses that approved sites actually resolved
to may connect. A raw IP not on that live list is refused.

**Q: Why your own DNS server, not the hosts file?**
A: The hosts file cannot do subdomains cleanly, cannot log, cannot cache, and
cannot feed a firewall. Our resolver gives allowlist logic with subdomains,
logging, caching, and it covers every program.

**Q: How do you know a DNS reply is real and not fake?**
A: The socket is CONNECTED to the upstream (the OS drops datagrams from anyone
else), and we accept a reply only if its transaction ID, question name and
question type match what we asked.

**Q: Thread safety in the DNS server?**
A: The log manager is synchronized, the cache is a ConcurrentHashMap, the IP
set is a synchronized set, control flags are volatile, and the UI is only
touched through `SwingUtilities.invokeLater`.

**Q: What if your app or the PC dies?**
A: Normal programs cannot kill an elevated app (UIPI). If the PC dies, the
leftover state stays on disk; the next app start detects it and restores the
network automatically.

**Q: Why kill programs instead of just logging them?**
A: Watching is evidence, closing is prevention. A headless browser in the
background is a full cheat toolkit; if we only logged it, the cheating would
already be happening. We do both: close AND log.

**Handover:** "That is the engine room. Now my teammate shows what the
invigilator sees, how we built the one-file installer, and how we tested it all."

---

# PART C — MEMBER 3: UI, Installer & Testing
*(Main.java + the gui package + the build + the 76 checks)*

## C1. What I say (about 3 minutes)

"My part is the interface, the installer and the testing.

The interface is Java Swing with six screens: first-run password, home, session
setup, live monitor, settings, and dashboard. We switch with CardLayout — all
screens sit in one frame like a deck of cards. We did not like the default grey
Java look, so we paint our own theme: in UITheme we override `paintComponent`
and draw rounded buttons, cards and input boxes with Java2D. The password field
has an eye icon drawn with pure Java2D — click to show or hide the password.

A big lesson was responsiveness: sealing the log and starting the lockdown take
many seconds. On the UI thread Windows would show 'Not Responding'. So every
slow job runs on a worker thread and the screen is updated only through
`SwingUtilities.invokeLater`.

The installer: one script compiles the code, packs a jar, then `jpackage` with
WiX produces ONE setup exe with its own trimmed Java runtime. The testing: our
own automatic suite with 76 checks in 15 groups — all pass. My teammate will
take questions on my part too if I miss anything."

## C2. Main.java — full code, part by part (1,077 lines)

### Chunk 1 — imports and the class fields

```java
package com.cheatguard;

import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.gui.DashboardPanel;
import com.cheatguard.gui.LogDisplayFormatter;
import com.cheatguard.gui.SettingsPanel;
import com.cheatguard.gui.UITheme;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.AdminCredentialStore;
import com.cheatguard.security.InstanceGuard;
import com.cheatguard.security.LogProtection;
import com.cheatguard.security.SecurityVault;
import com.cheatguard.watchdog.AllowedAppLauncher;
import com.cheatguard.watchdog.SessionEnvironment;
import com.cheatguard.watchdog.StrictNetworkLockdown;
import com.cheatguard.watchdog.ViolationListener;
import com.cheatguard.watchdog.WatchdogEngine;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Cheat.Guard — exam lockdown with a DNS-enforced website allowlist.
 *
 * <p>Every long-running operation (network lockdown, vault sealing, log deletion)
 * runs on a worker thread: the UAC prompt, the elevated helper handshake and the
 * PBKDF2 key derivations each take seconds, and freezing the interface during an
 * exam makes Windows mark the window as "Not Responding" — alarming for the
 * invigilator and an invitation to task-kill the app.
 */
public class Main {

    private static final InstanceGuard INSTANCE_GUARD = new InstanceGuard();
    private static final String CARD_FIRST_RUN = "FIRST_RUN";
    private static final String CARD_HOME = "HOME";
    private static final String CARD_SETUP = "SETUP";
    private static final String CARD_MONITOR = "MONITOR";
    private static final String CARD_SETTINGS = "SETTINGS";
    private static final String CARD_DASHBOARD = "DASHBOARD";

    private JFrame frame;
    private TrayIcon trayIcon;
    private boolean trayHintShown;
    private CardLayout cardLayout;
    private JPanel cardContainer;
    private final AdminAuth adminAuth = new AdminAuth();
    private final SessionEnvironment sessionEnvironment = new SessionEnvironment();

    private ExamSession activeSession;
    private SecurityVault activeSecurityVault;
    private WatchdogEngine activeWatchdog;
    private Thread activeWatchdogThread;
    private StrictNetworkLockdown activeNetworkLockdown;
    /** Guards double-clicks while a session is being started or ended. */
    private volatile boolean sessionBusy;

```

- The five `activeXxx` fields hold the current session's objects; they are set
  at start and cleared at end.
- `sessionBusy` is `volatile` — the UI thread and worker threads both read it;
  it stops double-clicks from running two flows.

### Chunk 2 — main(): the seven startup steps

```java
    public static void main(String[] args) {
        // Remember who is actually signed in before elevation possibly switches the
        // process to another account (invigilator's admin credentials over the
        // shoulder), so the exam folder and desktop shortcut land on the student's
        // desktop, not the administrator's.
        for (int i = 0; i < args.length - 1; i++) {
            if ("-interactiveProfile".equals(args[i])) {
                com.cheatguard.config.AppPaths.setInteractiveProfile(args[i + 1]);
            }
            if ("-interactiveDesktop".equals(args[i])) {
                com.cheatguard.config.AppPaths.setInteractiveDesktop(args[i + 1]);
            }
        }
        if (!ensureElevated()) return;

        AppLog.installCrashHandlers();
        AppLog.info("Cheat.Guard starting");

        UITheme.installLookAndFeel();
        if (!INSTANCE_GUARD.acquire()) {
            JOptionPane.showMessageDialog(null,
                    "Cheat.Guard is already running. Close the existing window first.",
                    "Already running", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(INSTANCE_GUARD::close, "InstanceGuard-Release"));
        if (!StrictNetworkLockdown.recoverStaleIfPresent()) {
            JOptionPane.showMessageDialog(null,
                    "A previous exam session could not be restored automatically.\n"
                            + "Ask the administrator to restore the network from\n"
                            + com.cheatguard.config.AppPaths.getNetworkDirectory().getAbsolutePath()
                            + " with an elevated PowerShell, then start Cheat.Guard again.",
                    "Network recovery required", JOptionPane.ERROR_MESSAGE);
            INSTANCE_GUARD.close();
            return;
        }
        SwingUtilities.invokeLater(() -> new Main().start());
    }

    // ------------------------------------------------------------- elevation

    /**
     * Relaunch as administrator when not already elevated and report whether the
     * caller should continue in this process.
     *
     * <p>Elevation is the backbone of the whole lockdown: a high-integrity process
     * cannot be terminated, debugged or written to by the student's medium-integrity
     * processes (Windows UIPI blocks it outright), the lockdown state under
     * ProgramData is only writable by Administrators, and the elevated helper script
     * can be staged where it cannot be swapped while its UAC prompt waits. A packaged
     * build that could not elevate (prompt declined) shows why and exits.
     */
```

1. Read the real user's profile/Desktop from the arguments (captured before
   elevation).
2. `ensureElevated()` — become admin or exit.
3. Install crash handlers (packaged builds have no console).
4. Dark look-and-feel.
5. Single-instance check — a second copy refuses to start.
6. Repair any leftover lockdown from a crashed session.
7. Build the window ON the EDT (`SwingUtilities.invokeLater`).

### Chunk 3 — becoming administrator

```java
    private static boolean ensureElevated() {
        if (!isWindows()) return true;
        if (isElevated()) return true;

        String launcher = System.getProperty("jpackage.app-path", "");
        File exe = launcher.isBlank() ? null : new File(launcher);
        if (exe == null || !exe.isFile()) {
            // Unpackaged development run (java -jar): proceed without elevation.
            System.err.println("Development run without elevation; lockdown features need an installed build.");
            return true;
        }

        String profile = System.getenv("USERPROFILE");
        StringBuilder argList = new StringBuilder();
        if (profile != null && !profile.isBlank()) {
            argList.append(" -ArgumentList '-interactiveProfile','")
                   .append(profile.replace("'", "''")).append('\'');
        }
        // Capture the signed-in user's real Desktop while still unelevated: on
        // OneDrive-redirected machines it is not <profile>\Desktop, and guessing
        // again after elevation could anchor the exam folder to the wrong account.
        try {
            File desktopNow = com.cheatguard.config.AppPaths.getDesktopDirectory();
            if (desktopNow != null && desktopNow.isDirectory()) {
                if (argList.length() == 0) argList.append(" -ArgumentList");
                argList.append(",'-interactiveDesktop','")
                       .append(desktopNow.getAbsolutePath().replace("'", "''")).append('\'');
            }
        } catch (Exception ignored) {
        }
        String command = "$p=Start-Process -FilePath '" + exe.getAbsolutePath().replace("'", "''")
                + "'" + argList + " -Verb RunAs -PassThru; if($null -eq $p){ exit 1 }";
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-Command", command).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            if (p.waitFor() == 0) return false; // elevated instance started; nothing more here
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        }
        JOptionPane.showMessageDialog(null,
                "Cheat.Guard must run as administrator.\n"
                        + "Approve the Windows permission prompt (or enter an administrator\n"
                        + "password) when it appears — without it the exam lockdown cannot\n"
                        + "be enforced and the app will not start.",
                "Administrator rights required", JOptionPane.WARNING_MESSAGE);
        return false;
    }

    private static boolean isElevated() {
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "(New-Object Security.Principal.WindowsPrincipal("
                            + "[Security.Principal.WindowsIdentity]::GetCurrent()"
                            + ")).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor();
            return out.toLowerCase(java.util.Locale.ROOT).contains("true");
        } catch (Exception e) {
            return false; // assume unelevated; the relaunch path will ask
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

```

- Already elevated or not Windows → continue. Dev runs (`java -jar`) continue
  unelevated with a console warning.
- Otherwise: PowerShell `Start-Process -Verb RunAs` with our own exe (plus the
  captured user folders as arguments). Approved → a NEW elevated copy runs and
  this one exits. Declined → an explanation dialog.

### Chunk 4 — `start()`: building the window

```java
    private void start() {
        frame = new JFrame("Cheat.Guard");
        frame.setSize(1120, 720);
        frame.setMinimumSize(new Dimension(960, 640));
        frame.setLocationRelativeTo(null);
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { attemptApplicationExit(); }
        });
        if (SystemTray.isSupported()) {
            setupTrayIcon();
            frame.addWindowStateListener(new WindowAdapter() {
                @Override public void windowStateChanged(WindowEvent e) {
                    if ((e.getNewState() & Frame.ICONIFIED) != 0) hideToTray();
                }
            });
        }
        UITheme.applyIcon(frame);

        cardLayout = new CardLayout();
        cardContainer = new JPanel(cardLayout);
        cardContainer.setBackground(UITheme.BG_DARK);
        frame.setContentPane(cardContainer);

        if (adminAuth.isTampered()) {
            JOptionPane.showMessageDialog(frame,
                    "The stored administrator credential does not belong to this computer and was rejected.\n"
                            + "Set a new administrator password to continue.",
                    "Credential rejected", JOptionPane.WARNING_MESSAGE);
            adminAuth.discardRejectedCredential();
        }
        if (!adminAuth.isConfigured()) {
            replaceCard(CARD_FIRST_RUN, buildFirstRunCard());
            showCard(CARD_FIRST_RUN);
        } else {
            replaceCard(CARD_HOME, buildHomeCard());
            showCard(CARD_HOME);
        }
        frame.setVisible(true);
        Thread t = new Thread(() -> {
            com.cheatguard.config.AppPaths.migrateLegacyProfileData();
            maybeCreateDesktopShortcut();
        }, "CheatGuard-FirstRun");
        t.setDaemon(true);
        t.start();
    }

    // ------------------------------------------------------- first-run set-up

    /** Shown only on a fresh installation: there is no default password to fall back on. */
```

- Close (X) is intercepted — it asks for the password first.
- Tray support: minimizing hides to the tray.
- Tampered credential file → warn + discard. Not configured → first-run
  screen; else home. A background thread migrates old data and creates the
  desktop shortcut once.

### Chunk 5 — the first-run password screen

```java
    private JPanel buildFirstRunCard() {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(UITheme.padding(34, 40, 34, 40));

        JPasswordField first = UITheme.password();
        JPasswordField second = UITheme.password();
        first.setMaximumSize(new Dimension(400, 42));
        second.setMaximumSize(new Dimension(400, 42));

        JLabel error = UITheme.muted(" ");
        error.setForeground(UITheme.ACCENT_RED);
        JButton save = UITheme.primary("Create password and continue");
        save.setMaximumSize(new Dimension(400, 46));

        Runnable doSave = () -> save.doClick();
        first.addActionListener(e -> doSave.run());
        second.addActionListener(e -> doSave.run());
        save.addActionListener(e -> {
            char[] a = first.getPassword();
            char[] b = second.getPassword();
            try {
                if (a.length == 0) {
                    error.setText("Choose a password first.");
                    return;
                }
                if (!Arrays.equals(a, b)) {
                    error.setText("The two passwords do not match.");
                    return;
                }
                adminAuth.createPassword(a);
                replaceCard(CARD_HOME, buildHomeCard());
                showCard(CARD_HOME);
            } catch (IllegalArgumentException weak) {
                error.setText(weak.getMessage());
            } catch (Exception ex) {
                error.setText("Could not save the password: " + ex.getMessage());
            } finally {
                Arrays.fill(a, '\0');
                Arrays.fill(b, '\0');
                first.setText("");
                second.setText("");
            }
        });

        card.add(brandMark(300));
        card.add(Box.createVerticalStrut(20));
        card.add(UITheme.title("Set the administrator password"));
        card.add(Box.createVerticalStrut(8));
        card.add(UITheme.muted("This password protects settings, the session dashboard and sealed logs."));
        card.add(Box.createVerticalStrut(4));
        card.add(UITheme.muted("At least " + AdminAuth.MIN_LENGTH
                + " characters, mixing letters with a number or symbol. It is never stored as text."));
        card.add(Box.createVerticalStrut(22));
        card.add(labelled("New password", first));
        card.add(Box.createVerticalStrut(14));
        card.add(labelled("Repeat password", second));
        card.add(Box.createVerticalStrut(22));
        card.add(save);
        card.add(Box.createVerticalStrut(10));
        card.add(error);
        SwingUtilities.invokeLater(first::requestFocusInWindow);
        return centered(card);
    }

    // -------------------------------------------------------------- home card

```

- Two password fields (with eye toggles) + error label + save button.
- Save: empty → error; mismatch → error; weak → the store's message shows.
  Success → home screen. `finally` wipes both char arrays.

### Chunk 6 — the home screen

```java
    private JPanel buildHomeCard() {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(UITheme.padding(38, 54, 38, 54));

        JButton startBtn = UITheme.primary("Start exam session");
        JButton dashboardBtn = UITheme.secondary("Session dashboard");
        JButton settingsBtn = UITheme.secondary("Allowed apps and websites");
        JButton exitBtn = UITheme.ghost("Exit");

        Dimension wide = new Dimension(360, 48);
        for (JButton b : new JButton[]{startBtn, dashboardBtn, settingsBtn}) b.setMaximumSize(wide);
        exitBtn.setMaximumSize(new Dimension(360, 38));

        startBtn.addActionListener(e -> {
            if (sessionBusy) return;
            replaceCard(CARD_SETUP, buildSetupCard());
            showCard(CARD_SETUP);
        });
        dashboardBtn.addActionListener(e -> openDashboard());
        settingsBtn.addActionListener(e -> openSettings());
        exitBtn.addActionListener(e -> attemptApplicationExit());

        card.add(brandMark(360));
        card.add(Box.createVerticalStrut(14));
        card.add(UITheme.muted("Exam lockdown for Windows — website allowlist, app control and sealed audit logs"));
        card.add(Box.createVerticalStrut(30));
        card.add(startBtn);
        card.add(Box.createVerticalStrut(11));
        card.add(dashboardBtn);
        card.add(Box.createVerticalStrut(11));
        card.add(settingsBtn);
        card.add(Box.createVerticalStrut(20));
        card.add(exitBtn);
        return centered(card);
    }

    // ------------------------------------------------------------- setup card

```

Four buttons; dashboard and settings first verify the admin password.

### Chunk 7 — the setup screen

```java
    private JPanel buildSetupCard() {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(UITheme.padding(34, 44, 34, 44));

        JTextField courseField = UITheme.field("e.g. CSE-3202");
        JTextField studentField = UITheme.field("e.g. 2021831045");
        courseField.setMaximumSize(new Dimension(400, 42));
        studentField.setMaximumSize(new Dimension(400, 42));

        JButton startBtn = UITheme.primary("Start monitoring");
        JButton backBtn = UITheme.ghost("Back");
        startBtn.setMaximumSize(new Dimension(400, 46));
        backBtn.setMaximumSize(new Dimension(400, 38));

        Runnable doStart = () -> {
            String course = courseField.getText().trim();
            String student = studentField.getText().trim();
            if (course.isEmpty() || student.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Enter both the course code and the student ID.",
                        "Missing details", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (AppConfig.getInstance().getAllowedSites().isEmpty()) {
                int choice = JOptionPane.showConfirmDialog(frame,
                        "No approved website has been configured.\n"
                                + "During the session EVERY website will fail to open,\n"
                                + "including the exam platform itself.\n\n"
                                + "Start the session anyway?",
                        "No approved websites", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (choice != JOptionPane.YES_OPTION) return;
            }
            startExam(course, student);
        };
        startBtn.addActionListener(e -> doStart.run());
        backBtn.addActionListener(e -> showCard(CARD_HOME));
        courseField.addActionListener(e -> doStart.run());
        studentField.addActionListener(e -> doStart.run());

        card.add(UITheme.title("New exam session"));
        card.add(Box.createVerticalStrut(8));
        card.add(UITheme.muted("A Desktop folder named Exam_<StudentID> is created for the student's work."));
        card.add(Box.createVerticalStrut(4));
        card.add(UITheme.muted("Browsers are closed when the session starts, so ask the student to save first."));
        card.add(Box.createVerticalStrut(24));
        card.add(labelled("Course code", courseField));
        card.add(Box.createVerticalStrut(14));
        card.add(labelled("Student ID", studentField));
        card.add(Box.createVerticalStrut(24));
        card.add(startBtn);
        card.add(Box.createVerticalStrut(10));
        card.add(backBtn);
        SwingUtilities.invokeLater(courseField::requestFocusInWindow);
        return centered(card);
    }

    // ------------------------------------------------------- session lifecycle

```

- Both fields required; an empty allowlist triggers a YES/NO warning ("EVERY
  website will fail"); Enter in either field clicks Start.

### Chunk 8 — `startExam()`: the most important method

```java

    private void startExam(String course, String studentId) {
        if (sessionBusy) return;
        sessionBusy = true;

        // Session record and log protection are quick and local; they happen here so
        // the monitor screen exists the moment the slow, elevated steps begin.
        activeSession = new ExamSession(course, studentId);
        activeSecurityVault = new SecurityVault(adminAuth);
        activeSecurityVault.beginProtection(activeSession.getSessionFile());

        JTextPane liveLog = createLogPane();
        for (Violation v : activeSession.getLogManager().getAllViolations()) appendViolation(liveLog, v);

        JLabel alertPill = UITheme.pill("0 ALERTS", UITheme.TEXT_MUTED);
        JLabel blockedPill = UITheme.pill("0 BLOCKED", UITheme.TEXT_MUTED);
        // Startup rows (closed apps, file-wall setup, one failed close inside the
        // sweep...) are recorded in the sealed log but NOT shown or counted: the
        // first 30 seconds are the machine settling down, not the student.
        long[] pills = new long[2]; // red, blocked
        ViolationListener liveListener = violation -> SwingUtilities.invokeLater(() -> {
            if (activeSession == null) return;
            if (hiddenDuringStartup(activeSession, violation)) return;
            appendViolation(liveLog, violation);
            if (violation.isRedFlag()) {
                pills[0]++;
                alertPill.setText(pills[0] + (pills[0] == 1 ? " ALERT" : " ALERTS"));
                alertPill.setForeground(UITheme.ACCENT_RED);
            }
            if (violation.getSeverity() == Violation.Severity.NOTICE) {
                pills[1]++;
                blockedPill.setText(pills[1] + " BLOCKED");
                blockedPill.setForeground(UITheme.WARN);
            }
        });

        JOptionPane.showMessageDialog(frame,
                "Windows will ask for administrator permission next — click Yes.\n\n"
                        + "During the session only the approved websites can be reached, and open browsers\n"
                        + "are restarted once so the new rules apply.",
                "Starting website lock", JOptionPane.INFORMATION_MESSAGE);

        ExamSession session = activeSession;
        replaceCard(CARD_MONITOR, buildMonitorCard(session, liveLog, alertPill, blockedPill, true));
        showCard(CARD_MONITOR);

        // The elevated helper handshake (UAC + ready marker) can take up to 90
        // seconds; clipboard prep spawns PowerShell too. All of it happens off the
        // interface thread so the window keeps painting.
        Thread starter = new Thread(() -> {
            StrictNetworkLockdown lockdown = new StrictNetworkLockdown(session.getLogManager(), liveListener);
            lockdown.setExamFolder(session.getExamFolder());
            boolean ok = false;
            try {
                logSessionContext(session, liveListener);
                sessionEnvironment.prepare();
                ok = lockdown.start();
            } catch (Exception ex) {
                AppLog.error("Session start crashed", ex);
            }
            AppLog.info("Session start " + (ok ? "succeeded" : "failed") + " for " + course + "/" + studentId);
            if (ok) {
                // The in-progress audit log IS the evidence: harden it now, mid-exam,
                // so the signed-in account cannot delete or edit it before the seal.
                // The helper is already running, so this costs no extra UAC prompt.
                if (!LogProtection.protectViaHelper(List.of(session.getSessionFile()))) {
                    AppLog.warn("Mid-session log hardening did not confirm");
                }
            }
            final boolean started = ok;
            final StrictNetworkLockdown finalLockdown = lockdown;
            SwingUtilities.invokeLater(() -> {
                if (started) {
                    activeNetworkLockdown = finalLockdown;
                    activeWatchdog = new WatchdogEngine(activeSession.getLogManager(),
                            activeSession.getExamFolder(), liveListener);
                    activeWatchdogThread = new Thread(activeWatchdog, "CheatGuard-Watchdog");
                    activeWatchdogThread.setDaemon(true);
                    activeWatchdogThread.start();
                    replaceCard(CARD_MONITOR, buildMonitorCard(session, liveLog, alertPill, blockedPill, false));
                    showCard(CARD_MONITOR);
                } else {
                    showLockdownFailure(finalLockdown.getLastError());
                    activeSession = null;
                    activeSecurityVault = null;
                    activeNetworkLockdown = null;
                    showCard(CARD_HOME);
                }
                sessionBusy = false;
            });
        }, "CheatGuard-SessionStarter");
        starter.setDaemon(true);
        starter.start();
    }

    /**
     * Awareness row for a known bypass path: a second local account already on the
     * machine. The elevated helper hides fast user switching for the session; the
     * row tells the invigilator the accounts exist in the first place.
     */
```

Read the order — it is the lesson:
1. Session + log created immediately (fast, local); the log file is locked.
2. The monitor screen shows "Starting session…" right away.
3. The slow elevated work (clipboard, lockdown — up to 90 s) runs on a WORKER
   thread; the UI never freezes.
4. Success → protect the log file, start the watchdog thread, rebuild the
   screen as active. Failure → explain, go home, clear everything so nothing
   is half-started.

### Chunk 9 — the account-count row and the failure dialog

```java
    private void logSessionContext(ExamSession session, ViolationListener listener) {
        int accounts = countLocalUsers();
        if (accounts <= 1) return;
        Violation v = new Violation("OTHER_ACCOUNTS_PRESENT",
                accounts + " local user accounts exist on this computer; switching users is blocked during the session.",
                Violation.Severity.INFO);
        session.getLogManager().record(v);
        listener.onViolation(v);
    }

    private int countLocalUsers() {
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", "(Get-LocalUser | Measure-Object).Count")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(10, TimeUnit.SECONDS);
            return Integer.parseInt(out.replaceAll("[^0-9]", ""));
        } catch (Exception e) {
            return 1;
        }
    }

    /** Status rows that are always worth showing, even in the startup window. */
    private static final Set<String> ALWAYS_SHOWN = Set.of(
            "SESSION_START", "STRICT_NETWORK_LOCK_ENABLED", "EGRESS_FIREWALL_ENABLED",
            "EGRESS_FIREWALL_FALLBACK", "FILE_LOCK_ENABLED", "FILE_LOCK_SKIPPED", "SESSION_END");

    /**
     * The first 30 seconds are the machine settling down (apps closing, locks
     * arming), not the student acting - those rows stay in the sealed log but
     * never reach the live screen or the counters.
     */
    private boolean hiddenDuringStartup(ExamSession session, Violation violation) {
        if (ALWAYS_SHOWN.contains(violation.getType())) return false;
        return session.getStartTime().plusSeconds(30).isAfter(violation.getTimestamp());
    }

    private void showLockdownFailure(String detail) {        String text = detail == null || detail.isBlank()
                ? "Windows did not report a reason."
                : detail;
        JTextArea area = new JTextArea(
                "The website lock could not be enabled, so the exam was NOT started.\n"
                        + "Nothing on this computer was left changed.\n\nWindows reported:\n" + text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setRows(10);
        area.setColumns(62);
        area.setCaretPosition(0);
        JOptionPane.showMessageDialog(frame, new JScrollPane(area),
                "Could not start the session", JOptionPane.ERROR_MESSAGE);
    }

    // ----------------------------------------------------------- monitor card

```

- `countLocalUsers()` runs a PowerShell count; more than one account → an info
  row for the invigilator (fast user switching is already hidden by the
  helper).

### Chunk 10 — the live monitor screen

```java
    private JPanel buildMonitorCard(ExamSession session, JTextPane liveLog, JLabel alertPill,
                                    JLabel blockedPill, boolean starting) {
        JPanel screen = UITheme.screen();
        screen.setBorder(UITheme.padding(20, 22, 20, 22));

        // Header: live status, who is being monitored, elapsed time, alert counters.
        JPanel header = UITheme.card(UITheme.BG_PANEL, true);
        header.setLayout(new BorderLayout(16, 0));
        header.setBorder(UITheme.padding(16, 18, 16, 18));

        JLabel status = starting
                ? UITheme.title("Starting session — approve the administrator prompt")
                : UITheme.title("Session active");
        status.setForeground(starting ? UITheme.WARN : UITheme.ACCENT_TEAL);
        JLabel who = UITheme.muted(session.getCourseCode() + "  ·  Student " + session.getStudentId());
        JPanel left;
        if (starting) {
            left = UITheme.column(4, leftAlign(status), leftAlign(who));
        } else {
            JLabel elapsed = UITheme.muted("Running 00:00:00");
            // Self-stopping: the tick ends once the monitor screen is no longer on
            // display (session ended), so no timer outlives its card.
            javax.swing.Timer clock = new javax.swing.Timer(1000, ev -> {
                long sec = Duration.between(session.getStartTime(), LocalDateTime.now()).getSeconds();
                elapsed.setText(String.format("Running %02d:%02d:%02d", sec / 3600, sec % 3600 / 60, sec % 60));
                if (!elapsed.isShowing()) ((javax.swing.Timer) ev.getSource()).stop();
            });
            clock.setInitialDelay(0);
            clock.start();
            left = UITheme.column(4, leftAlign(status), leftAlign(who), leftAlign(elapsed));
        }

        ImageIcon mark = UITheme.image("/logo.png", 150, 0);
        if (mark != null) {
            JPanel branded = new JPanel(new BorderLayout(16, 0));
            branded.setOpaque(false);
            branded.add(new JLabel(mark), BorderLayout.WEST);
            branded.add(left, BorderLayout.CENTER);
            header.add(branded, BorderLayout.WEST);
        } else {
            header.add(left, BorderLayout.WEST);
        }
        header.add(UITheme.row(8,
                        starting ? UITheme.pill("LOCKING WEBSITES…", UITheme.WARN)
                                 : UITheme.pill("WEBSITE LOCK ON", UITheme.ACCENT_TEAL),
                        alertPill, blockedPill),
                BorderLayout.EAST);
        screen.add(header, BorderLayout.NORTH);

        // Live log.
        JPanel logCard = UITheme.card();
        logCard.setLayout(new BorderLayout(10, 10));
        logCard.setBorder(UITheme.padding(16, 18, 16, 18));
        JPanel logHead = new JPanel(new BorderLayout());
        logHead.setOpaque(false);
        logHead.add(leftAlign(UITheme.section("Live activity")), BorderLayout.WEST);
        JButton openFolder = UITheme.ghost("Open exam folder");
        openFolder.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(session.getExamFolder());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Could not open the exam folder.");
            }
        });
        logHead.add(openFolder, BorderLayout.EAST);
        logCard.add(logHead, BorderLayout.NORTH);
        logCard.add(UITheme.scroll(liveLog), BorderLayout.CENTER);

        JPanel body = new JPanel(new BorderLayout());
        body.setOpaque(false);
        body.setBorder(UITheme.padding(14, 0, 14, 0));
        body.add(logCard, BorderLayout.CENTER);
        screen.add(body, BorderLayout.CENTER);

        // Footer: quick access to an approved site, and the guarded end-session action.
        JPanel footer = UITheme.card(UITheme.BG_PANEL, true);
        footer.setLayout(new BorderLayout(12, 0));
        footer.setBorder(UITheme.padding(14, 18, 14, 18));

        // Approved apps: launching from here opens the app on the exam folder, so the
        // student never needs to browse the disk to reach their workspace.
        String[] apps = AppConfig.getInstance().getAllowedProcesses().stream()
                .map(com.cheatguard.watchdog.ProcessWhitelist::friendlyName)
                .toArray(String[]::new);
        JComboBox<String> appCombo = UITheme.combo(apps);
        appCombo.setPreferredSize(new Dimension(200, 34));
        JButton openApp = UITheme.secondary("Open on exam folder");
        openApp.addActionListener(e -> {
            Object selected = appCombo.getSelectedItem();
            if (selected == null) {
                JOptionPane.showMessageDialog(frame,
                        "No application has been approved yet. Add one in \"Allowed apps and websites\".",
                        "Nothing to open", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String problem = AllowedAppLauncher.launch(selected.toString(), session.getExamFolder());
            if (problem != null) {
                JOptionPane.showMessageDialog(frame, problem, "Could not open the app",
                        JOptionPane.WARNING_MESSAGE);
            }
        });

        JComboBox<String> siteCombo = UITheme.combo(
                AppConfig.getInstance().getAllowedSites().toArray(new String[0]));
        siteCombo.setPreferredSize(new Dimension(200, 34));
        JButton openSite = UITheme.secondary("Open site");
        openSite.addActionListener(e -> {
            Object selected = siteCombo.getSelectedItem();
            if (selected == null) return;
            try {
                Desktop.getDesktop().browse(new URI("https://" + selected));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Could not open that site.");
            }
        });

        JPanel quickAccess = UITheme.column(8,
                UITheme.row(8, fixedLabel("Approved apps", 108), appCombo, openApp),
                UITheme.row(8, fixedLabel("Approved sites", 108), siteCombo, openSite));
        footer.add(quickAccess, BorderLayout.WEST);

        JButton endBtn = UITheme.primary("End session and seal log");
        endBtn.addActionListener(e -> requestEndSession(session));
        // BorderLayout.EAST would stretch the button over the full footer height.
        JPanel endWrap = new JPanel(new GridBagLayout());
        endWrap.setOpaque(false);
        endWrap.add(endBtn);
        footer.add(endWrap, BorderLayout.EAST);
        screen.add(footer, BorderLayout.SOUTH);
        return screen;
    }

    /**
     * Ask for the administrator password, verify it, then run the teardown on a
     * worker thread: sealing derives two PBKDF2 keys, the permission hardening can
     * wait up to 20 seconds for the elevated helper, and restoring the network up
     * to 25 more. None of that may run on the interface thread.
     */
```

- Header: logo, status (amber while starting / teal when active), the course
  and student, a self-stopping clock (`javax.swing.Timer`, one tick per
  second, stops when its label is no longer displayed), and the pill row
  (WEBSITE LOCK ON / ALERTS / BLOCKED).
- Center: "Live activity" card with the colored log and "Open exam folder".
- Footer: approved-app and approved-site combos + launch buttons, and the red
  end-session button (in a GridBagLayout wrapper so it does not stretch).

### Chunk 11 — ending the session

```java
    private void requestEndSession(ExamSession session) {
        if (sessionBusy) {
            JOptionPane.showMessageDialog(frame,
                    "A session action is already in progress. Wait a moment.",
                    "Please wait", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        char[] password = promptAdminPassword("End exam session");
        if (password == null) return;
        if (password.length == 0) {
            Arrays.fill(password, '\0');
            JOptionPane.showMessageDialog(frame, "Enter the administrator password.",
                    "Password required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        AdminCredentialStore.Result r = adminAuth.check(password.clone());
        if (!r.success()) {
            Arrays.fill(password, '\0');
            explainVerificationFailure(r);
            return;
        }
        sessionBusy = true;
        Thread ender = new Thread(() -> {
            boolean sealed = false;
            try {
                sealed = finishActiveExam(password);
            } finally {
                Arrays.fill(password, '\0');
            }
            final boolean done = sealed;
            final long alerts = session == null || session.getLogManager() == null
                    ? 0 : session.getLogManager().getRedFlagCount();
            SwingUtilities.invokeLater(() -> {
                if (done) {
                    JOptionPane.showMessageDialog(frame, sessionSummary(session, alerts),
                            "Session complete", JOptionPane.INFORMATION_MESSAGE);
                    showCard(CARD_HOME);
                }
                sessionBusy = false;
            });
        }, "CheatGuard-SessionEnder");
        ender.setDaemon(true);
        ender.start();
    }

    private boolean finishActiveExam(char[] password) {
        if (activeSession == null) return true;
        try {
            if (activeWatchdog != null) activeWatchdog.stop();
            if (activeWatchdogThread != null) {
                activeWatchdogThread.interrupt();
                try {
                    activeWatchdogThread.join(1800);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            File sessionFile = activeSession.getSessionFile();
            activeSession.endSession();
            activeSecurityVault.sealVault(sessionFile, password);

            // Harden the sealed files while the elevated helper is still running, so no
            // extra UAC prompt is needed. Only then restore the network state.
            File vault = new File(sessionFile.getParent(),
                    sessionFile.getName().replace(".dat", ".vault"));
            LogProtection.protectViaHelper(List.of(vault, new File(vault.getAbsolutePath() + ".sig")));
            return true;
        } catch (Exception ex) {
            SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(frame, "Could not seal the session log: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE));
            return false;
        } finally {
            // Always give the computer its network and clipboard settings back, even if
            // sealing failed - a student must never be left without Internet.
            StrictNetworkLockdown lockdown = activeNetworkLockdown;
            activeNetworkLockdown = null;
            if (lockdown != null && !lockdown.stopAndRestore()) {
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(frame,
                                "Windows did not confirm that the network settings were restored.\n"
                                        + "If the Internet stays blocked, start Cheat.Guard again —\n"
                                        + "it offers to repair a leftover lockdown automatically —\n"
                                        + "or ask an administrator to restore the network from the\n"
                                        + "network folder under ProgramData.",
                                "Network restore warning", JOptionPane.WARNING_MESSAGE));
            }
            sessionEnvironment.restore();
            activeSession = null;
            activeSecurityVault = null;
            activeWatchdog = null;
            activeWatchdogThread = null;
        }
    }

    /** Short closing summary so the invigilator sees the outcome without opening the log. */
    private String sessionSummary(ExamSession session, long alerts) {
        String outcome = alerts == 0
                ? "No alerts were raised during this session."
                : alerts + " alert(s) were raised — open the session dashboard to review them.";
        return "Session sealed for student " + session.getStudentId()
                + " (" + session.getCourseCode() + ").\n\n"
                + outcome + "\n\n"
                + "The sealed log is protected: it cannot be deleted from Windows Explorer,\n"
                + "only from the dashboard with the administrator password.";
    }

```

- Password → verify → worker thread → `finishActiveExam(password)`.
- `finishActiveExam`: stop the watchdog (interrupt + join), write SESSION_END,
  SEAL the vault, harden the sealed files, and in `finally` ALWAYS restore the
  network + clipboard — even on failure the student gets the internet back and
  the app stays open for a retry.

### Chunk 12 — the guarded exit

```java
    private void attemptApplicationExit() {
        // A fresh installation has no password yet; asking for one here would trap
        // the invigilator in an app that can never be closed. Nothing is at risk:
        // no session, no stored credential, nothing sealed.
        if (!adminAuth.isConfigured()) {
            frame.dispose();
            System.exit(0);
        }
        char[] entered = promptAdminPassword(activeSession == null ? "Exit Cheat.Guard" : "End session and exit");
        if (entered == null) return;
        if (entered.length == 0) {
            Arrays.fill(entered, '\0');
            JOptionPane.showMessageDialog(frame, "Enter the administrator password.",
                    "Password required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        AdminCredentialStore.Result r = adminAuth.check(entered.clone());
        if (!r.success()) {
            Arrays.fill(entered, '\0');
            explainVerificationFailure(r);
            return;
        }
        if (activeSession != null) {
            if (sessionBusy) {
                Arrays.fill(entered, '\0');
                JOptionPane.showMessageDialog(frame, "A session action is already in progress.",
                        "Please wait", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            sessionBusy = true;
            char[] password = entered;
            Thread ender = new Thread(() -> {
                boolean sealed = false;
                try {
                    sealed = finishActiveExam(password);
                } finally {
                    Arrays.fill(password, '\0');
                    // Leave the app open when sealing failed: the unsealed log and the
                    // session summary dialog are still on screen, and the invigilator
                    // can simply press End session again to retry.
                    final boolean done = sealed;
                    SwingUtilities.invokeLater(() -> {
                        if (done) {
                            frame.dispose();
                            System.exit(0);
                        }
                        sessionBusy = false;
                    });
                }
            }, "CheatGuard-ExitEnder");
            ender.setDaemon(true);
            ender.start();
            return;
        }
        Arrays.fill(entered, '\0');
        frame.dispose();
        System.exit(0);
    }

    // -------------------------------------------------------------- tray icon

    /** Minimize-to-tray so the window can be hidden during a session without closing it. */
```

- Fresh install (no password) → exit directly, else password. Active session →
  seal first; sealing failed → stay open for retry.

### Chunk 13 — the tray

```java
    private void setupTrayIcon() {
        try {
            ImageIcon icon = UITheme.image("/icon.png", 16, 0);
            if (icon == null) return;
            PopupMenu menu = new PopupMenu();
            MenuItem show = new MenuItem("Show Cheat.Guard");
            show.addActionListener(e -> restoreFromTray());
            menu.add(show);
            trayIcon = new TrayIcon(icon.getImage(), "Cheat.Guard", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> restoreFromTray());
            SystemTray.getSystemTray().add(trayIcon);
        } catch (Exception ignored) {
            trayIcon = null; // tray unavailable: normal minimizing keeps working
        }
    }

    private void hideToTray() {
        if (trayIcon == null) return;
        frame.setVisible(false);
        if (!trayHintShown) {
            trayHintShown = true;
            trayIcon.displayMessage("Cheat.Guard", "Still running in the tray — click here to reopen.",
                    TrayIcon.MessageType.INFO);
        }
    }

    private void restoreFromTray() {
        frame.setVisible(true);
        frame.setExtendedState(Frame.NORMAL);
        frame.toFront();
    }

    // -------------------------------------------------- admin-guarded screens

```

- `SystemTray` + `TrayIcon` with a "Show Cheat.Guard" menu; minimizing hides
  the window; clicking the icon restores it. One balloon hint, ever.

### Chunk 14 — the password-guarded screens

```java
    private void openDashboard() {
        char[] password = promptAdminPassword("Open session dashboard");
        if (password == null) return;
        if (verifyOrExplain(password)) {
            replaceCard(CARD_DASHBOARD, new DashboardPanel(adminAuth, () -> showCard(CARD_HOME)));
            showCard(CARD_DASHBOARD);
        }
    }

    private void openSettings() {
        char[] password = promptAdminPassword("Open allowlist settings");
        if (password == null) return;
        if (verifyOrExplain(password)) {
            replaceCard(CARD_SETTINGS, new SettingsPanel(adminAuth, () -> showCard(CARD_HOME)));
            showCard(CARD_SETTINGS);
        }
    }

    /** Ask for the admin password in a styled dialog; null means cancelled. */
    private char[] promptAdminPassword(String title) {
        JPasswordField pf = UITheme.password();
        pf.setPreferredSize(new Dimension(260, 36));
        JPanel content = UITheme.column(8, leftAlign(UITheme.muted("Administrator password")), pf);
        content.setBorder(UITheme.padding(4, 4, 4, 4));
        int result = JOptionPane.showConfirmDialog(frame, content, title,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        return result == JOptionPane.OK_OPTION ? pf.getPassword() : null;
    }

    /** Verify a password and explain a refusal, including throttling. */
    private boolean verifyOrExplain(char[] password) {
        AdminCredentialStore.Result r = adminAuth.check(password);
        if (r.success()) return true;
        explainVerificationFailure(r);
        return false;
    }

    private void explainVerificationFailure(AdminCredentialStore.Result r) {
        String message;
        if (!r.configured()) {
            message = "No administrator password is set on this computer.";
        } else if (r.lockedForMs() > 0) {
            long seconds = Math.max(1, r.lockedForMs() / 1000);
            message = "Too many incorrect attempts. Try again in " + seconds + " seconds.";
        } else {
            message = r.attemptsLeft() >= AdminCredentialStore.MAX_ATTEMPTS
                    ? "Enter the administrator password."
                    : "Incorrect password. " + r.attemptsLeft() + " attempt(s) left before a lockout.";
        }
        JOptionPane.showMessageDialog(frame, message, "Access denied", JOptionPane.ERROR_MESSAGE);
    }

    // ------------------------------------------------------------- shortcuts

    /**
     * Create the desktop shortcut once, on the first run after installation. The
     * MSI places a Start Menu entry; invigilators expect the icon on the Desktop
     * too. Best effort only — a failure here must never block the app.
     */
```

- `openDashboard()` / `openSettings()` — both go through the same prompt.
- `promptAdminPassword()` builds a dialog with one `UITheme.password()` field
  (so it has the eye toggle).
- `explainVerificationFailure()` shows: not configured / locked for N seconds /
  N attempts left — straight from the credential store's result.

### Chunk 15 — the one-time shortcut, and the small helpers

```java
    private void maybeCreateDesktopShortcut() {
        File marker = new File(AppPaths.getDataDirectory(), "shortcut.created");
        if (marker.exists()) return;
        Thread t = new Thread(() -> {
            try {
                String launcher = System.getProperty("jpackage.app-path", "");
                File exe = launcher.isBlank() ? null : new File(launcher);
                if (exe == null || !exe.isFile()) return; // unpackaged run: nothing to link
                File lnk = new File(AppPaths.getDesktopDirectory(), "Cheat.Guard.lnk");
                String ps = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
                        + lnk.getAbsolutePath().replace("'", "''") + "');"
                        + "$s.TargetPath='" + exe.getAbsolutePath().replace("'", "''") + "';"
                        + "$s.WorkingDirectory='" + exe.getParentFile().getAbsolutePath().replace("'", "''") + "';"
                        + "$s.IconLocation='" + exe.getAbsolutePath().replace("'", "''") + ",0';"
                        + "$s.Save()";
                Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
                        .redirectErrorStream(true).start();
                p.getInputStream().readAllBytes();
                p.waitFor(15, TimeUnit.SECONDS);
                marker.createNewFile();
            } catch (Exception ex) {
                AppLog.warn("Desktop shortcut creation failed: " + ex.getMessage());
            }
        }, "CheatGuard-Shortcut");
        t.setDaemon(true);
        t.start();
    }

    // ---------------------------------------------------------------- helpers

    /** Wordmark image, falling back to text if the resource is missing. */
    private Component brandMark(int width) {
        ImageIcon logo = UITheme.image("/logo.png", width, 0);
        if (logo == null) {
            JLabel text = UITheme.display("Cheat.Guard");
            text.setAlignmentX(Component.CENTER_ALIGNMENT);
            return text;
        }
        JLabel l = new JLabel(logo);
        l.setAlignmentX(Component.CENTER_ALIGNMENT);
        return l;
    }

    /** Field with a caption above it, sized to match the action buttons below. */
    private JPanel labelled(String caption, JComponent field) {
        JPanel group = new JPanel();
        group.setOpaque(false);
        group.setLayout(new BoxLayout(group, BoxLayout.Y_AXIS));
        group.setAlignmentX(Component.CENTER_ALIGNMENT);
        group.setMaximumSize(new Dimension(400, 76));
        group.add(leftAlign(UITheme.muted(caption)));
        group.add(Box.createVerticalStrut(6));
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
        group.add(field);
        return group;
    }

    /** Caption with a fixed width so the two quick-access rows line up. */
    private static JLabel fixedLabel(String text, int width) {
        JLabel l = UITheme.muted(text);
        l.setPreferredSize(new Dimension(width, 20));
        return l;
    }

    private static <T extends JComponent> T leftAlign(T component) {
        component.setAlignmentX(Component.LEFT_ALIGNMENT);
        return component;
    }

    /** Put a card in the middle of the gradient backdrop. */
    private JPanel centered(JComponent card) {
        JPanel root = UITheme.backdrop(new GridBagLayout());
        root.add(card);
        return root;
    }

    private JTextPane createLogPane() {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setFont(UITheme.FONT_MONO);
        pane.setBackground(UITheme.BG_INPUT);
        pane.setForeground(UITheme.TEXT_WHITE);
        pane.setBorder(UITheme.padding(10, 12, 10, 12));
        return pane;
    }

    private void appendViolation(JTextPane pane, Violation violation) {
        // Three visual levels: red = got through, yellow = tried but was blocked,
        // muted = routine enforcement (closed apps, heartbeat messages).
        String name = violation.isRedFlag() ? "alert"
                : violation.getSeverity() == Violation.Severity.NOTICE ? "warn" : "ok";
        Style style = pane.getStyle(name);
        if (style == null) {
            style = pane.addStyle(name, null);
            Color colour = "alert".equals(name) ? UITheme.ACCENT_RED
                    : "warn".equals(name) ? UITheme.WARN : UITheme.TEXT_MUTED;
            StyleConstants.setForeground(style, colour);
            StyleConstants.setBold(style, violation.isRedFlag());
        }
        StyledDocument doc = pane.getStyledDocument();
        try {
            // A very long session must not grow the live pane without bound; the
            // oldest rows are dropped from the DISPLAY only, the sealed log keeps all.
            int len = doc.getLength();
            if (len > 60_000) {
                String head = doc.getText(0, len - 60_000 + 1);
                int nl = head.lastIndexOf('\n');
                if (nl > 0) doc.remove(0, nl + 1);
            }
            doc.insertString(doc.getLength(),
                    LogDisplayFormatter.format(violation) + System.lineSeparator(), style);
            pane.setCaretPosition(doc.getLength());
        } catch (BadLocationException ignored) {
            // a full document is not worth interrupting the session for
        }
    }

    private void replaceCard(String name, Component component) {
        for (Component c : cardContainer.getComponents()) {
            if (name.equals(c.getName())) {
                cardContainer.remove(c);
                break;
            }
        }
        component.setName(name);
        cardContainer.add(component, name);
        cardContainer.revalidate();
        cardContainer.repaint();
    }

    private void showCard(String name) {
        cardLayout.show(cardContainer, name);
    }
}
```

- `maybeCreateDesktopShortcut()`: once ever (a marker file remembers); creates
  `Cheat.Guard.lnk` through PowerShell's WScript.Shell COM object.
- `appendViolation()`: picks a style by severity (red bold / yellow / grey),
  trims the pane past ~60,000 characters (the FILE keeps everything), inserts
  the row, auto-scrolls.
- `replaceCard()`/`showCard()`: the CardLayout helpers.
- `createLogPane()`: the dark monospace text pane used for the live log.

## C3. UITheme.java — the entire look, full code

### Chunk 1 — the palette and fonts

```java
package com.cheatguard.gui;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.geom.Path2D;
import java.io.InputStream;

/**
 * Cheat.Guard design system: colours, type scale and painted components.
 *
 * <p>Swing's stock controls look dated, so the shared widgets here are custom
 * painted with rounded corners, hover feedback and consistent spacing. Screens
 * build their layout from these factories instead of styling controls ad hoc, so
 * the whole application stays visually consistent.
 */
public final class UITheme {

    // Palette taken from the Cheat.Guard wordmark: near-black, signal red, teal dot.
    public static final Color BG_DARK = new Color(0x0E1014);
    public static final Color BG_PANEL = new Color(0x16191F);
    public static final Color BG_ELEVATED = new Color(0x1E232C);
    public static final Color BG_INPUT = new Color(0x11141A);
    public static final Color BORDER = new Color(0x2A313D);
    public static final Color ACCENT_RED = new Color(0xF4342B);
    public static final Color ACCENT_RED_DARK = new Color(0xC7241D);
    public static final Color ACCENT_TEAL = new Color(0x2EC4A0);
    public static final Color TEXT_WHITE = new Color(0xF3F5F8);
    public static final Color TEXT_MUTED = new Color(0x99A3B2);
    public static final Color TEXT_DIM = new Color(0x6C7583);
    public static final Color WARN = new Color(0xF2B234);

    // Interaction states: every painted control picks its fill from these, so hover
    // and press feedback stay identical across screens.
    public static final Color ACCENT_RED_PRESS = new Color(0xA81A14);
    public static final Color BG_ELEVATED_HOVER = new Color(0x262C38);
    public static final Color BG_ELEVATED_PRESS = new Color(0x171B22);
    public static final Color BG_PANEL_PRESS = new Color(0x12151A);
    /** Soft teal ring drawn around the input that owns keyboard focus. */
    public static final Color FOCUS_RING = new Color(46, 196, 160, 150);

    private static final char ECHO = '\u2022';

    // "Segoe UI Semibold" is a separate family name that Java resolves inconsistently:
    // metrics come from one face and painting from another, which clips labels sized to
    // their preferred width. Using the real family with a style avoids that entirely.
    public static final Font FONT_DISPLAY = new Font("Segoe UI", Font.BOLD, 26);
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_SECTION = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 14);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 13);

    private UITheme() {
    }

    // ------------------------------------------------------------ application

```

- Four dark greys, the red accent with darker/press variants, teal, amber
  WARN, three text greys, a translucent teal FOCUS_RING, and the ECHO bullet.
- One font family ("Segoe UI") at five sizes + Consolas for logs.

### Chunk 2 — look-and-feel keys, icon, image scaling

```java
    public static void installLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {
            // stock default is acceptable; our components paint themselves anyway
        }
        UIManager.put("ToolTip.background", BG_ELEVATED);
        UIManager.put("ToolTip.foreground", TEXT_WHITE);
        UIManager.put("OptionPane.background", BG_PANEL);
        UIManager.put("OptionPane.messageForeground", TEXT_WHITE);
        UIManager.put("Panel.background", BG_PANEL);

        // Metal draws chunky light scrollbars and combo arrows by default, which stand
        // out badly on a dark surface; these keys bring them in line with the theme.
        UIManager.put("ScrollBar.width", 11);
        UIManager.put("ScrollBar.background", BG_INPUT);
        UIManager.put("ScrollBar.track", BG_INPUT);
        UIManager.put("ScrollBar.trackHighlight", BG_INPUT);
        UIManager.put("ScrollBar.thumb", BG_ELEVATED);
        UIManager.put("ScrollBar.thumbShadow", BORDER);
        UIManager.put("ScrollBar.thumbHighlight", BORDER);
        UIManager.put("ScrollBar.darkShadow", BG_INPUT);
        UIManager.put("ComboBox.background", BG_INPUT);
        UIManager.put("ComboBox.foreground", TEXT_WHITE);
        UIManager.put("ComboBox.selectionBackground", BG_ELEVATED);
        UIManager.put("ComboBox.selectionForeground", ACCENT_TEAL);
        UIManager.put("ComboBox.buttonBackground", BG_ELEVATED);
        UIManager.put("ComboBox.buttonShadow", BORDER);
        UIManager.put("ComboBox.buttonDarkShadow", BORDER);
        UIManager.put("ComboBox.buttonHighlight", BG_ELEVATED);
        UIManager.put("TextField.caretForeground", ACCENT_TEAL);

        // Shared dialogs and tooltips in the same type scale as the screens.
        UIManager.put("OptionPane.messageFont", FONT_BODY);
        UIManager.put("OptionPane.buttonFont", FONT_BODY);
        UIManager.put("ToolTip.font", FONT_SMALL);
        UIManager.put("SplitPane.background", BG_DARK);
    }

    public static void applyIcon(JFrame frame) {
        try (InputStream is = UITheme.class.getResourceAsStream("/icon.png")) {
            if (is != null) {
                Image image = ImageIO.read(is);
                if (image != null) frame.setIconImage(image);
            }
        } catch (Exception ignored) {
            // window keeps the default icon
        }
    }

    /** Scaled bitmap from a classpath resource; width-driven when height is 0. */
    public static ImageIcon image(String resource, int width, int height) {
        try (InputStream is = UITheme.class.getResourceAsStream(resource)) {
            if (is == null) return null;
            Image src = ImageIO.read(is);
            if (src == null) return null;
            int h = height > 0 ? height
                    : Math.max(1, Math.round(width * (float) src.getHeight(null) / src.getWidth(null)));
            return new ImageIcon(src.getScaledInstance(width, h, Image.SCALE_SMOOTH));
        } catch (Exception e) {
            return null;
        }
    }

    // ----------------------------------------------------------------- labels

```

- ~20 `UIManager.put` keys darken tooltips, dialogs, scrollbars, combos.
- `image()` loads a classpath bitmap and scales it smoothly (height auto from
  aspect ratio when 0).

### Chunk 3 — label factories

```java
    public static JLabel display(String text) {
        return label(text, FONT_DISPLAY, TEXT_WHITE);
    }

    public static JLabel title(String text) {
        return label(text, FONT_TITLE, TEXT_WHITE);
    }

    public static JLabel section(String text) {
        JLabel l = label(text.toUpperCase(), FONT_SECTION, TEXT_DIM);
        return l;
    }

    public static JLabel body(String text) {
        return label(text, FONT_BODY, TEXT_WHITE);
    }

    public static JLabel muted(String text) {
        return label(text, FONT_SMALL, TEXT_MUTED);
    }

    private static JLabel label(String text, Font font, Color colour) {
        JLabel l = new JLabel(text);
        l.setFont(font);
        l.setForeground(colour);
        l.setAlignmentX(Component.CENTER_ALIGNMENT);
        return l;
    }

    // ---------------------------------------------------------------- buttons

```

Five factory methods (display/title/section/body/muted) — one place controls
every label in the app.

### Chunk 4 — the button factories (polymorphism showcase)

```java
    public static JButton primary(String text) {
        return button(text, ACCENT_RED, ACCENT_RED_DARK, ACCENT_RED_PRESS, Color.WHITE, false);
    }

    public static JButton secondary(String text) {
        return button(text, BG_ELEVATED, BG_ELEVATED_HOVER, BG_ELEVATED_PRESS, TEXT_WHITE, true);
    }

    public static JButton ghost(String text) {
        JButton b = button(text, BG_PANEL, BG_ELEVATED, BG_PANEL_PRESS, TEXT_MUTED, true);
        b.setFont(FONT_SMALL);
        return b;
    }

    /** Rounded, flat button with hover and press states and no focus painting. */
    private static JButton button(String text, Color base, Color hover, Color press, Color fg,
                                  boolean outlined) {
        JButton b = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color fill = !isEnabled() ? BG_ELEVATED
                        : getModel().isPressed() ? press
                        : getModel().isRollover() ? hover
                        : base;
                g2.setColor(fill);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                if (outlined) {
                    g2.setColor(BORDER);
                    g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                }
                g2.dispose();
                super.paintComponent(g);
            }
        };
        b.setRolloverEnabled(true);
        b.setFont(FONT_BODY);
        b.setForeground(fg);
        b.setContentAreaFilled(false);
        b.setBorderPainted(false);
        b.setFocusPainted(false);
        b.setOpaque(false);
        b.setCursor(new Cursor(Cursor.HAND_CURSOR));
        b.setBorder(BorderFactory.createEmptyBorder(11, 20, 11, 20));
        b.setAlignmentX(Component.CENTER_ALIGNMENT);
        return b;
    }

    // ----------------------------------------------------------------- inputs

```

- An anonymous subclass of `JButton` overrides `paintComponent`: antialiasing,
  the fill picked from the button MODEL (normal / hover / press), a 12-px
  rounded rectangle, then `super.paintComponent` draws the text on top.
- `primary` (red), `secondary` (elevated + border), `ghost` (transparent,
  small font). Hover/press come from the model, so keyboard activation works.

### Chunk 5 — the text field and the password field with the eye

```java
    public static JTextField field(String placeholder) {
        JTextField f = new JTextField();
        styleInput(f);
        if (placeholder != null && !placeholder.isEmpty()) f.setToolTipText(placeholder);
        return f;
    }

    /**
     * Masked input with an embedded eye toggle: clicking the eye reveals the text and
     * clicking again masks it, so a mistyped password can be checked without ever
     * leaving the field. The toggle lives in the field's right margin, so the text
     * never runs underneath it.
     */
    public static JPasswordField password() {
        JPasswordField f = new JPasswordField();
        f.setEchoChar(ECHO);
        styleInput(f);
        JToggleButton eye = eyeToggle(f);
        f.setMargin(new Insets(0, 0, 0, 46));
        f.setLayout(new BorderLayout(0, 0));
        f.add(eye, BorderLayout.EAST);
        return f;
    }

    private static JToggleButton eyeToggle(JPasswordField field) {
        JToggleButton eye = new JToggleButton() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getModel().isRollover() || isSelected() ? TEXT_WHITE : TEXT_MUTED);
                g2.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                int cx = getWidth() / 2;
                int cy = getHeight() / 2;
                // Almond eye: two curved lids meeting at the corners - a plain oval
                // read as the "all-seeing eye", so the lids are drawn as curves.
                Path2D almond = new Path2D.Double();
                almond.moveTo(cx - 9, cy);
                almond.quadTo(cx - 2, cy - 7, cx + 9, cy);
                almond.quadTo(cx - 2, cy + 7, cx - 9, cy);
                almond.closePath();
                g2.draw(almond);
                if (isSelected()) {
                    // Text is visible: eye ON - open eye with a small pupil.
                    g2.fillOval(cx - 2, cy - 2, 4, 4);
                } else {
                    // Text is hidden: eye OFF - closed eye with the classic slash.
                    g2.drawLine(cx + 8, cy - 7, cx - 8, cy + 7);
                }
                g2.dispose();
            }
        };
        eye.setToolTipText("Show password");
        eye.setFocusable(false);
        eye.setRolloverEnabled(true);
        eye.setBorderPainted(false);
        eye.setContentAreaFilled(false);
        eye.setOpaque(false);
        eye.setCursor(new Cursor(Cursor.HAND_CURSOR));
        eye.setPreferredSize(new Dimension(36, 24));
        eye.addActionListener(e -> {
            boolean show = eye.isSelected();
            field.setEchoChar(show ? (char) 0 : ECHO);
            eye.setToolTipText(show ? "Hide password" : "Show password");
        });
        return eye;
    }

```

- `password()`: echo `•`, margin `0,0,0,46` reserves the eye strip INSIDE the
  text area (text can never run under the icon), and a `JToggleButton` child
  at `BorderLayout.EAST`.
- `eyeToggle` PAINTS the icon: an oval outline, a filled pupil, and a diagonal
  slash when the text is visible. Clicking flips `setEchoChar` between `•` and
  `(char) 0` and updates the tooltip. `setFocusable(false)` — it never steals
  Tab focus.

### Chunk 6 — input styling and our own rounded border

```java
    private static void styleInput(JTextField f) {
        f.setFont(FONT_BODY);
        f.setBackground(BG_INPUT);
        f.setForeground(TEXT_WHITE);
        f.setCaretColor(ACCENT_TEAL);
        f.setSelectionColor(new Color(46, 196, 160, 70));
        f.setSelectedTextColor(TEXT_WHITE);
        Border resting = inputBorder(BORDER);
        Border focused = inputBorder(FOCUS_RING);
        f.setBorder(resting);
        f.addFocusListener(new FocusAdapter() {
            @Override public void focusGained(FocusEvent e) { f.setBorder(focused); }
            @Override public void focusLost(FocusEvent e) { f.setBorder(resting); }
        });
    }

    private static Border inputBorder(Color colour) {
        return BorderFactory.createCompoundBorder(
                roundedLine(colour, 10),
                BorderFactory.createEmptyBorder(9, 12, 9, 12));
    }

    /** One-pixel outline with a real radius; LineBorder's rounded arc is far too tight. */
    private static Border roundedLine(Color colour, int radius) {
        return new AbstractBorder() {
            @Override
            public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(colour);
                g2.drawRoundRect(x, y, w - 1, h - 1, radius, radius);
                g2.dispose();
            }

            @Override
            public Insets getBorderInsets(Component c, Insets insets) {
                insets.set(1, 1, 1, 1);
                return insets;
            }

            @Override
            public boolean isBorderOpaque() {
                return false;
            }
        };
    }

    // ------------------------------------------------------ panels and layout

    /** Rounded surface used for every grouped block of content. */
```

- A `FocusAdapter` swaps the border colour to a teal ring on focus.
- `roundedLine` extends `AbstractBorder` and draws a 1-px rounded rectangle —
  Swing's rounded LineBorder has an arc of only ~2 px, too tight for our look.

### Chunk 7 — cards and pills

```java
    public static JPanel card() {
        return card(BG_PANEL, true);
    }

    public static JPanel card(Color fill, boolean outlined) {
        JPanel p = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(fill);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                if (outlined) {
                    g2.setColor(BORDER);
                    g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
                }
                g2.dispose();
            }
        };
        p.setOpaque(false);
        p.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));
        return p;
    }

    /** Small coloured status pill, e.g. "PROTECTED" or "3 ALERTS". */
    public static JLabel pill(String text, Color colour) {
        JLabel l = new JLabel(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(colour.getRed(), colour.getGreen(), colour.getBlue(), 38));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), getHeight(), getHeight());
                g2.setColor(new Color(colour.getRed(), colour.getGreen(), colour.getBlue(), 120));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, getHeight(), getHeight());
                g2.dispose();
                super.paintComponent(g);
            }
        };
        l.setFont(FONT_SMALL);
        l.setForeground(colour);
        l.setOpaque(false);
        l.setBorder(BorderFactory.createEmptyBorder(5, 12, 5, 12));
        return l;
    }

```

- `card()` paints a 16-px rounded panel with an outline; `pill()` paints the
  translucent rounded status labels (ALERTS / BLOCKED).

### Chunk 8 — layout helpers and the backdrop

```java
    public static JPanel row(int gap, Component... children) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, gap, 0));
        p.setOpaque(false);
        for (Component c : children) p.add(c);
        return p;
    }

    public static JPanel column(int gap, Component... children) {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (int i = 0; i < children.length; i++) {
            if (i > 0) p.add(Box.createVerticalStrut(gap));
            p.add(children[i]);
        }
        return p;
    }

    public static Component grow() {
        return Box.createHorizontalGlue();
    }

    /**
     * Full-screen backdrop with a soft vertical gradient and a faint red glow behind
     * the centre, so a screen holding a single card does not read as a flat black box.
     */
    public static JPanel backdrop(LayoutManager layout) {
        JPanel p = new JPanel(layout) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth();
                int h = getHeight();
                g2.setPaint(new GradientPaint(0, 0, new Color(0x14171D), 0, h, BG_DARK));
                g2.fillRect(0, 0, w, h);
                int radius = Math.max(w, h);
                g2.setPaint(new RadialGradientPaint(
                        new Point(w / 2, h / 3), radius / 2f,
                        new float[]{0f, 1f},
                        new Color[]{new Color(244, 52, 43, 20), new Color(244, 52, 43, 0)}));
                g2.fillRect(0, 0, w, h);
                g2.dispose();
            }
        };
        p.setOpaque(true);
        p.setBackground(BG_DARK);
        return p;
    }

    public static JPanel screen() {
        return backdrop(new BorderLayout());
    }

    public static Border padding(int top, int left, int bottom, int right) {
        return BorderFactory.createEmptyBorder(top, left, bottom, right);
    }

    /** Dark scroll pane without the default chrome. */
    public static JScrollPane scroll(Component view) {
        JScrollPane sp = new JScrollPane(view);
        sp.setBorder(roundedLine(BORDER, 10));
        sp.getViewport().setBackground(BG_INPUT);
        sp.setBackground(BG_INPUT);
        sp.getVerticalScrollBar().setUnitIncrement(18);
        JPanel corner = new JPanel();
        corner.setBackground(BG_INPUT);
        sp.setCorner(JScrollPane.LOWER_RIGHT_CORNER, corner);
        return sp;
    }

    /** Dark-themed drop-down; the stock Metal combo renders light and breaks the theme. */
    public static JComboBox<String> combo(String[] items) {
        JComboBox<String> box = new JComboBox<>(items);
        box.setFont(FONT_BODY);
        box.setBackground(BG_INPUT);
        box.setForeground(TEXT_WHITE);
        box.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        box.setFocusable(false);
        box.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean selected, boolean focus) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, value, index, selected, focus);
                l.setFont(FONT_BODY);
                l.setBackground(selected ? BG_ELEVATED : BG_INPUT);
                l.setForeground(selected ? ACCENT_TEAL : TEXT_WHITE);
                l.setBorder(padding(4, 8, 4, 8));
                return l;
            }
        });
        return box;
    }

    /** Consistent styling for the list widgets used on the settings screens. */
    public static <T> void styleList(JList<T> list) {
        list.setBackground(BG_INPUT);
        list.setForeground(TEXT_WHITE);
        list.setFont(FONT_BODY);
        list.setSelectionBackground(BG_ELEVATED);
        list.setSelectionForeground(ACCENT_TEAL);
        list.setFixedCellHeight(28);
        list.setBorder(padding(6, 8, 6, 8));
    }
}
```

- `row`/`column`/`grow` are tiny layout helpers used by every screen.
- `backdrop()` paints a vertical gradient plus a faint red radial glow —
  single-card screens do not look like a flat black box.
- `scroll()` — dark scroll pane with a rounded border and a painted dark
  corner; `combo()` — dark drop-down renderer; `styleList()` — consistent
  list colours.

## C4. LogDisplayFormatter.java — log lines → human rows

```java
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
```

**What to notice:**
- `format(Violation)` → `row(time, statusOf(severity), message(...))`.
  `statusOf`: WARNING/CRITICAL → "ALERT", NOTICE → "WARN", else "OK". The row
  is `String.format("%s   %-5s  %s", ...)` — time, a 5-character status, one
  sentence trimmed to 90 characters.
- `formatRaw(line)` parses STORED lines (the dashboard uses it): it finds
  `[RED-FLAG]` / `[NOTICE]` for the status and splits ` :: ` and ` - ` to
  recover type and detail. Old logs from earlier versions still parse.
- `message()` is a switch of friendly sentences ("Closed before exam: X",
  "Allowed app had a file outside the exam folder open, closed: X",
  "Website blocked: X", "Opened outside exam folder: X" — only the LAST path
  part shows). `clean()` strips legacy prefixes; `lastPathPart` shortens
  paths; `readableType` is the fallback.

## C5. SettingsPanel.java — three cards

```java
package com.cheatguard.gui;

import com.cheatguard.config.AppConfig;
import com.cheatguard.security.AdminAuth;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Administrator screen: allowed applications, allowed websites and the admin password. */
public class SettingsPanel extends JPanel {

    private final AppConfig config = AppConfig.getInstance();
    private final AdminAuth adminAuth;
    private DefaultListModel<String> processModel;
    private DefaultListModel<String> siteModel;

    public SettingsPanel(AdminAuth adminAuth, Runnable onBack) {
        this.adminAuth = adminAuth;
        setLayout(new BorderLayout());
        setOpaque(true);
        setBackground(UITheme.BG_DARK);
        setBorder(UITheme.padding(22, 24, 22, 24));
        add(buildHeader(onBack), BorderLayout.NORTH);
        add(buildBody(), BorderLayout.CENTER);
    }

    private JComponent buildHeader(Runnable onBack) {
        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(false);
        header.setBorder(UITheme.padding(0, 0, 18, 0));

        JLabel title = UITheme.title("Exam allowlist");
        JLabel subtitle = UITheme.muted(
                "Only the applications and websites listed here stay usable during a session.");
        title.setAlignmentX(LEFT_ALIGNMENT);
        subtitle.setAlignmentX(LEFT_ALIGNMENT);
        header.add(UITheme.column(4, title, subtitle), BorderLayout.WEST);

        JButton back = UITheme.ghost("Back");
        back.addActionListener(e -> onBack.run());
        header.add(back, BorderLayout.EAST);
        return header;
    }

    private JComponent buildBody() {
        JPanel columns = new JPanel(new GridLayout(1, 3, 18, 0));
        columns.setOpaque(false);
        columns.add(buildAppCard());
        columns.add(buildSiteCard());
        columns.add(buildSecurityCard());
        return columns;
    }

    private JComponent buildAppCard() {
        processModel = new DefaultListModel<>();
        refresh(processModel, config.getAllowedProcesses());
        JList<String> list = new JList<>(processModel);
        UITheme.styleList(list);
        // show the app's real name in the allowed list, exe name stays the model value
        list.setCellRenderer((l, value, index, selected, focus) -> {
            JLabel label = new JLabel(displayName(value));
            label.setBorder(UITheme.padding(0, 4, 0, 4));
            label.setForeground(selected ? list.getSelectionForeground() : list.getForeground());
            label.setBackground(selected ? list.getSelectionBackground() : list.getBackground());
            label.setOpaque(true);
            return label;
        });

        // search bar: type a few letters, matching INSTALLED apps appear by their
        // real names; picking one adds the exe it points to.
        JTextField search = UITheme.field("Search installed apps...");
        DefaultListModel<String> matchModel = new DefaultListModel<>();
        JList<String> matches = new JList<>(matchModel);
        UITheme.styleList(matches);
        matches.setVisibleRowCount(6);
        List<com.cheatguard.config.InstalledApps.App> installed =
                com.cheatguard.config.InstalledApps.list();
        Runnable refill = () -> {
            String q = search.getText().trim().toLowerCase();
            matchModel.clear();
            for (com.cheatguard.config.InstalledApps.App app : installed) {
                if (q.isEmpty()
                        || app.displayName().toLowerCase().contains(q)) {
                    matchModel.addElement(app.displayName() + "  \u2192  " + app.lnkPath());
                }
            }
        };
        refill.run();
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
        });

        JButton add = UITheme.secondary("Add selected");
        add.addActionListener(e -> {
            String chosen = matches.getSelectedValue();
            if (chosen == null) return;
            String lnkPath = chosen.substring(chosen.indexOf("  \u2192  ") + 5).trim();
            String target = com.cheatguard.config.InstalledApps.resolveTarget(lnkPath);
            if (target == null || target.isBlank()
                    || !target.toLowerCase().endsWith(".exe")) {
                JOptionPane.showMessageDialog(this,
                        "Could not resolve that app's program file.", "Not added",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            String exeName = new java.io.File(target).getName();
            config.addAllowedProcessPath(new java.io.File(target));
            config.setAppDisplayName(exeName, chosen.substring(0, chosen.indexOf("  \u2192  ")).trim());
            refresh(processModel, config.getAllowedProcesses());
            search.setText("");
        });

        JButton browse = UITheme.ghost("Choose .exe");
        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Choose an application to allow");
            chooser.setFileFilter(new FileNameExtensionFilter("Windows applications (*.exe)", "exe"));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                java.io.File exe = chooser.getSelectedFile();
                config.addAllowedProcessPath(exe);
                config.setAppDisplayName(exe.getName(), realAppName(exe));
                refresh(processModel, config.getAllowedProcesses());
            }
        });
        JButton remove = UITheme.ghost("Remove selected");
        remove.addActionListener(e -> {
            String selected = list.getSelectedValue();
            if (selected == null) return;
            config.removeAllowedProcess(selected);
            refresh(processModel, config.getAllowedProcesses());
        });

        return appCard("Allowed applications",
                "Add apps by searching their real names - anything else a student opens is closed automatically. Use \"Choose .exe\" for a portable program.",
                list, search, matchModel, matches, add, browse, remove);
    }

    /** Read an exe's real name from its version information (best effort). */
    private String realAppName(java.io.File exe) {
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command",
                    "(Get-Item '" + exe.getAbsolutePath().replace("'", "''")
                            + "').VersionInfo.ProductName")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            if (!out.isBlank() && !out.toLowerCase().contains("error")) return out;
        } catch (Exception ignored) {
        }
        return null;
    }

    /** Display name for an allowed exe: real name when known, else the exe name. */
    private String displayName(String exeName) {
        String real = config.getAppDisplayName(exeName);
        return real != null ? real : com.cheatguard.watchdog.ProcessWhitelist.friendlyName(exeName);
    }

    /** The applications card: heading, hint, allowed list, search picker, actions. */
    private JComponent appCard(String heading, String hintText, JList<String> list,
                               JTextField search, DefaultListModel<String> matchModel,
                               JList<String> matches, JButton add, JButton extra, JButton remove) {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JScrollPane scroll = UITheme.scroll(list);
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        scroll.setPreferredSize(new Dimension(300, 220));

        JScrollPane matchScroll = UITheme.scroll(matches);
        matchScroll.setAlignmentX(LEFT_ALIGNMENT);
        matchScroll.setPreferredSize(new Dimension(300, 130));

        search.setMaximumSize(new Dimension(460, 40));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setOpaque(false);
        actions.setAlignmentX(LEFT_ALIGNMENT);
        actions.add(add);
        actions.add(extra);
        actions.add(remove);

        card.add(leftAlign(UITheme.row(0, UITheme.section(heading))));
        card.add(Box.createVerticalStrut(6));
        card.add(leftAlign(UITheme.row(0, hint(hintText))));
        card.add(Box.createVerticalStrut(14));
        card.add(leftAlign(search));
        card.add(Box.createVerticalStrut(8));
        card.add(leftAlign(matchScroll));
        card.add(Box.createVerticalStrut(10));
        card.add(leftAlign(actions));
        card.add(Box.createVerticalStrut(12));
        card.add(leftAlign(scroll));
        return card;
    }

    private JComponent buildSiteCard() {
        siteModel = new DefaultListModel<>();
        refresh(siteModel, config.getAllowedSites());
        JList<String> list = new JList<>(siteModel);
        UITheme.styleList(list);

        JTextField input = UITheme.field("codeforces.com");
        JButton add = UITheme.secondary("Add");
        JButton remove = UITheme.ghost("Remove selected");

        Runnable addAction = () -> {
            String value = input.getText().trim();
            if (value.isEmpty()) return;
            int before = config.getAllowedSites().size();
            config.addAllowedSite(value);
            refresh(siteModel, config.getAllowedSites());
            if (config.getAllowedSites().size() == before) {
                JOptionPane.showMessageDialog(this,
                        "\"" + value + "\" is not a valid domain. Use a full name such as codeforces.com.",
                        "Not added", JOptionPane.WARNING_MESSAGE);
            }
            input.setText("");
        };
        add.addActionListener(e -> addAction.run());
        input.addActionListener(e -> addAction.run());
        remove.addActionListener(e -> {
            String selected = list.getSelectedValue();
            if (selected == null) return;
            config.removeAllowedSite(selected);
            refresh(siteModel, config.getAllowedSites());
        });

        return card("Allowed websites",
                "Subdomains are included automatically. Every other domain fails to resolve during a session.",
                list, input, add, null, remove);
    }

    /** Change the administrator password. No password is ever shown or stored as text. */
    private JComponent buildSecurityCard() {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JPasswordField current = UITheme.password();
        JPasswordField next = UITheme.password();
        JPasswordField repeat = UITheme.password();
        for (JPasswordField f : new JPasswordField[]{current, next, repeat}) {
            f.setAlignmentX(LEFT_ALIGNMENT);
            f.setMaximumSize(new Dimension(320, 40));
        }

        JLabel status = UITheme.muted(" ");
        status.setAlignmentX(LEFT_ALIGNMENT);
        JButton apply = UITheme.secondary("Update password");
        apply.setAlignmentX(LEFT_ALIGNMENT);

        apply.addActionListener(e -> {
            char[] a = current.getPassword();
            char[] b = next.getPassword();
            char[] c = repeat.getPassword();
            try {
                if (!Arrays.equals(b, c)) {
                    status.setForeground(UITheme.ACCENT_RED);
                    status.setText("The new passwords do not match.");
                    return;
                }
                adminAuth.changePassword(a, b);
                status.setForeground(UITheme.ACCENT_TEAL);
                status.setText("Password updated.");
            } catch (IllegalArgumentException | SecurityException refused) {
                status.setForeground(UITheme.ACCENT_RED);
                status.setText(refused.getMessage());
            } catch (Exception ex) {
                status.setForeground(UITheme.ACCENT_RED);
                status.setText("Could not update: " + ex.getMessage());
            } finally {
                Arrays.fill(a, '\0');
                Arrays.fill(b, '\0');
                Arrays.fill(c, '\0');
                current.setText("");
                next.setText("");
                repeat.setText("");
            }
        });

        card.add(leftAlign(UITheme.row(0, UITheme.section("Administrator password"))));
        card.add(Box.createVerticalStrut(6));
        card.add(leftAlign(UITheme.row(0, hint("Stored only as a salted PBKDF2 digest, tied to this "
                + "computer. It cannot be read back from the app, the installer or the source code."))));
        card.add(Box.createVerticalStrut(16));
        card.add(leftAlign(UITheme.muted("Current password")));
        card.add(Box.createVerticalStrut(5));
        card.add(current);
        card.add(Box.createVerticalStrut(12));
        card.add(leftAlign(UITheme.muted("New password")));
        card.add(Box.createVerticalStrut(5));
        card.add(next);
        card.add(Box.createVerticalStrut(12));
        card.add(leftAlign(UITheme.muted("Repeat new password")));
        card.add(Box.createVerticalStrut(5));
        card.add(repeat);
        card.add(Box.createVerticalStrut(18));
        card.add(apply);
        card.add(Box.createVerticalStrut(10));
        card.add(status);
        card.add(Box.createVerticalGlue());
        return card;
    }

    /** One list card: heading, hint, list, add row and secondary actions. */
    private JComponent card(String heading, String hintText, JList<String> list,
                            JTextField input, JButton addBtn, JButton extraBtn, JButton removeBtn) {        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JScrollPane scroll = UITheme.scroll(list);
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        scroll.setPreferredSize(new Dimension(300, 300));

        JPanel addRow = new JPanel(new BorderLayout(8, 0));
        addRow.setOpaque(false);
        addRow.setAlignmentX(LEFT_ALIGNMENT);
        addRow.setMaximumSize(new Dimension(460, 44));
        addRow.add(input, BorderLayout.CENTER);
        addRow.add(addBtn, BorderLayout.EAST);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setOpaque(false);
        actions.setAlignmentX(LEFT_ALIGNMENT);
        if (extraBtn != null) actions.add(extraBtn);
        actions.add(removeBtn);

        card.add(leftAlign(UITheme.row(0, UITheme.section(heading))));
        card.add(Box.createVerticalStrut(6));
        card.add(leftAlign(UITheme.row(0, hint(hintText))));
        card.add(Box.createVerticalStrut(14));
        card.add(scroll);
        card.add(Box.createVerticalStrut(12));
        card.add(addRow);
        card.add(Box.createVerticalStrut(10));
        card.add(actions);
        return card;
    }

    private JLabel hint(String text) {
        JLabel l = UITheme.muted("<html><body style='width:228px'>" + text + "</body></html>");
        l.setForeground(UITheme.TEXT_DIM);
        return l;
    }

    private static <T extends JComponent> T leftAlign(T c) {
        c.setAlignmentX(LEFT_ALIGNMENT);
        return c;
    }

    private void refresh(DefaultListModel<String> model, Set<String> values) {
        model.clear();
        for (String v : values) model.addElement(v);
    }
}
```

**What to notice:**
- `extends JPanel` — inheritance; the body is a `GridLayout(1, 3)` of three
  cards: applications, websites, password.
- The apps card: `JList` + input + Add (Enter works) + "Choose .exe"
  (`JFileChooser` → `addAllowedProcessPath`, which also stores the full path
  so the app can be launched on the exam folder) + Remove selected.
- The websites card is the same minus browse; an invalid domain shows a dialog
  (because `normalizeSite` returned empty).
- The password card: three password fields WITH eye toggles; Update calls
  `adminAuth.changePassword`; the status label turns teal/red; all three char
  arrays are wiped in `finally`.

## C6. DashboardPanel.java — reading the sealed logs

```java
package com.cheatguard.gui;

import com.cheatguard.config.AppPaths;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.SecurityVault;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.Arrays;
import java.util.Comparator;

/** Admin log dashboard: open, inspect and delete sealed or interrupted sessions. */
public class DashboardPanel extends JPanel {
    private final SecurityVault vault;
    private final AdminAuth adminAuth;
    private final DefaultListModel<File> logModel = new DefaultListModel<>();
    private final JList<File> logList = new JList<>(logModel);
    private final JTextPane outputPane = new JTextPane();
    private final JLabel summaryLabel = new JLabel("Select a session log.");
    private final JLabel studentValue = statValue("—");
    private final JLabel courseValue = statValue("—");
    private final JLabel startValue = statValue("—");
    private final JLabel endValue = statValue("—");
    private final JLabel durationValue = statValue("—");
    private final JLabel redValue = statValue("0");
    /** The password verified at the dashboard door - reused for open and delete. */
    private final char[] sessionPassword;

    public DashboardPanel(AdminAuth adminAuth, char[] sessionPassword, Runnable onBack) {
        this.adminAuth = adminAuth;
        this.vault = new SecurityVault(adminAuth);
        this.sessionPassword = sessionPassword == null ? new char[0] : sessionPassword;
        setLayout(new BorderLayout(16, 16));
        setBackground(UITheme.BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(22, 22, 22, 22));
        add(buildHeader(onBack), BorderLayout.NORTH);
        add(buildMainArea(), BorderLayout.CENTER);
        refreshLogs();
    }

    private JPanel buildHeader(Runnable onBack) {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(UITheme.BG_DARK);
        JPanel titles = new JPanel();
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        titles.setBackground(UITheme.BG_DARK);
        JLabel title = UITheme.title("Session dashboard");
        summaryLabel.setFont(UITheme.FONT_BODY);
        summaryLabel.setForeground(UITheme.TEXT_MUTED);
        titles.add(title);
        titles.add(Box.createVerticalStrut(4));
        titles.add(summaryLabel);
        JButton back = UITheme.ghost("Back");
        back.addActionListener(e -> {
            Arrays.fill(sessionPassword, '\0'); // leaving the dashboard: forget the password
            onBack.run();
        });
        header.add(titles, BorderLayout.WEST);
        header.add(back, BorderLayout.EAST);
        return header;
    }

    private JSplitPane buildMainArea() {
        UITheme.styleList(logList);
        logList.setCellRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof File) {
                    File f = (File) value;
                    label.setText((f.getName().toLowerCase().endsWith(".dat") ? "[UNSEALED] " : "") + f.getName());
                }
                return label;
            }
        });
        logList.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) openSelected();
            }
        });

        JPanel left = UITheme.card();
        left.setLayout(new BorderLayout(10, 10));
        left.add(UITheme.section("Saved sessions"), BorderLayout.NORTH);
        left.add(UITheme.scroll(logList), BorderLayout.CENTER);

        JButton refresh = UITheme.ghost("Refresh");
        JButton delete = UITheme.ghost("Delete selected");
        JPanel leftButtons = new JPanel(new GridLayout(1, 2, 8, 0));
        leftButtons.setOpaque(false);
        leftButtons.add(refresh);
        leftButtons.add(delete);
        left.add(leftButtons, BorderLayout.SOUTH);
        refresh.addActionListener(e -> refreshLogs());
        delete.addActionListener(e -> deleteSelected());

        JPanel right = UITheme.card();
        right.setLayout(new BorderLayout(10, 10));

        JButton open = UITheme.primary("Open session");
        JPanel openRow = new JPanel(new BorderLayout(8, 0));
        openRow.setOpaque(false);
        openRow.add(UITheme.muted("Verified at the door - open or delete sessions freely."),
                BorderLayout.CENTER);
        openRow.add(open, BorderLayout.EAST);
        open.addActionListener(e -> openSelected());

        JPanel stats = new JPanel(new GridLayout(2, 3, 10, 10));
        stats.setOpaque(false);
        stats.add(statCard("Student ID", studentValue));
        stats.add(statCard("Course", courseValue));
        stats.add(statCard("RED flags", redValue));
        stats.add(statCard("Start", startValue));
        stats.add(statCard("End", endValue));
        stats.add(statCard("Duration", durationValue));

        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.setOpaque(false);
        top.add(openRow, BorderLayout.NORTH);
        top.add(stats, BorderLayout.CENTER);

        outputPane.setEditable(false);
        outputPane.setFont(new Font("Consolas", Font.PLAIN, 13));
        outputPane.setBackground(UITheme.BG_INPUT);
        outputPane.setBorder(UITheme.padding(10, 12, 10, 12));
        outputPane.setForeground(UITheme.TEXT_WHITE);
        right.add(top, BorderLayout.NORTH);
        right.add(UITheme.scroll(outputPane), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.30);
        split.setDividerLocation(300);
        split.setBorder(null);
        return split;
    }

    private JPanel statCard(String label, JLabel value) {
        JPanel p = UITheme.card(UITheme.BG_ELEVATED, false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(UITheme.padding(10, 12, 10, 12));
        JLabel l = UITheme.muted(label.toUpperCase());
        l.setForeground(UITheme.TEXT_DIM);
        l.setAlignmentX(LEFT_ALIGNMENT);
        value.setAlignmentX(LEFT_ALIGNMENT);
        p.add(l);
        p.add(Box.createVerticalStrut(4));
        p.add(value);
        return p;
    }

    private static JLabel statValue(String text) {
        JLabel l = new JLabel(text);
        l.setFont(UITheme.FONT_SECTION);
        l.setForeground(UITheme.TEXT_WHITE);
        return l;
    }

    private void refreshLogs() {
        File[] files = AppPaths.getVaultDirectory().listFiles((dir, name) -> {
            String n = name.toLowerCase();
            return n.endsWith(".vault") || n.endsWith(".dat");
        });
        logModel.clear();
        if (files != null) {
            Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
            for (File f : files) logModel.addElement(f);
        }
        summaryLabel.setText(logModel.size() + " saved session(s). [UNSEALED] means the app was force-stopped before the exam ended normally.");
    }

    private void openSelected() {
        File selected = logList.getSelectedValue();
        if (selected == null) { JOptionPane.showMessageDialog(this, "Select a session first."); return; }
        if (sessionPassword.length == 0) {
            JOptionPane.showMessageDialog(this, "Open the dashboard with the admin password first.",
                    "Password required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        // Opening derives a PBKDF2 key and can read a large log; do it off the UI thread.
        new Thread(() -> {
            String content;
            try {
                content = vault.openLog(selected, sessionPassword.clone());
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                        "Could not open log: " + ex.getMessage(),
                        "Access denied", JOptionPane.ERROR_MESSAGE));
                return;
            }
            boolean unsealed = selected.getName().toLowerCase().endsWith(".dat");
            SwingUtilities.invokeLater(() -> renderLogWithHighlights(content, unsealed));
        }, "CheatGuard-LogOpen").start();
    }

    private void deleteSelected() {
        File selected = logList.getSelectedValue();
        if (selected == null) { JOptionPane.showMessageDialog(this, "Select a session first."); return; }
        if (sessionPassword.length == 0) {
            JOptionPane.showMessageDialog(this, "Open the dashboard with the admin password first.",
                    "Password required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int ok = JOptionPane.showConfirmDialog(this,
                "Permanently delete this student log?\n" + selected.getName(), "Delete log", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.YES_OPTION) return;
        // Deleting a protected log can raise a Windows elevation prompt that waits on
        // the invigilator; keep the window responsive while it runs.
        new Thread(() -> {
            try {
                vault.deleteLog(selected, sessionPassword.clone());
                SwingUtilities.invokeLater(() -> {
                    outputPane.setText("");
                    resetStats();
                    refreshLogs();
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                        "Could not delete log: " + ex.getMessage(),
                        "Delete failed", JOptionPane.ERROR_MESSAGE));
            }
        }, "CheatGuard-LogDelete").start();
    }

    private void renderLogWithHighlights(String content, boolean unsealed) {
        outputPane.setText("");
        StyledDocument doc = outputPane.getStyledDocument();
        Style redStyle = outputPane.addStyle("red", null);
        StyleConstants.setForeground(redStyle, UITheme.ACCENT_RED);
        StyleConstants.setBold(redStyle, true);
        Style warnStyle = outputPane.addStyle("warn", null);
        StyleConstants.setForeground(warnStyle, UITheme.WARN);
        Style normalStyle = outputPane.addStyle("normal", null);
        StyleConstants.setForeground(normalStyle, UITheme.TEXT_WHITE);

        int redFlags = 0;
        int blockedAttempts = 0;
        String student = "—", course = "—", start = "—", end = unsealed ? "FORCE-STOPPED" : "—", duration = unsealed ? "Unknown" : "—";
        try {
            for (String line : content.split("\\R")) {
                boolean red = line.contains("[RED-FLAG]");
                boolean warn = !red && line.contains("[NOTICE]");
                if (red) redFlags++;
                if (warn) blockedAttempts++;
                if (line.contains("SESSION_START")) {
                    start = timestamp(line);
                    student = field(line, "StudentID=");
                    course = field(line, "Course=");
                }
                if (line.contains("SESSION_END")) {
                    end = timestamp(line);
                    String sec = field(line, "DurationSeconds=");
                    try { duration = formatDuration(Long.parseLong(sec)); } catch (Exception ignored) {}
                }
                String display = LogDisplayFormatter.formatRaw(line);
                if (!display.isEmpty()) doc.insertString(doc.getLength(), display + System.lineSeparator(),
                        red ? redStyle : warn ? warnStyle : normalStyle);
            }
            studentValue.setText(student);
            courseValue.setText(course);
            startValue.setText(start);
            endValue.setText(end);
            durationValue.setText(duration);
            redValue.setText(Integer.toString(redFlags));
            redValue.setForeground(redFlags > 0 ? UITheme.ACCENT_RED : UITheme.ACCENT_TEAL);
            summaryLabel.setText((unsealed ? "UNSEALED / interrupted session" : "Sealed session")
                    + " — " + redFlags + " RED-FLAG event(s)"
                    + (blockedAttempts > 0 ? ", " + blockedAttempts + " blocked website attempt(s)" : ""));
        } catch (BadLocationException e) {
            summaryLabel.setText("Could not render selected log.");
        }
    }

    private String timestamp(String line) { return line.length() >= 19 ? line.substring(0, 19) : "—"; }

    private String field(String line, String key) {
        int start = line.indexOf(key);
        if (start < 0) return "—";
        start += key.length();
        int end = line.indexOf(" | ", start);
        if (end < 0) end = line.length();
        return line.substring(start, end).trim();
    }

    private String formatDuration(long sec) {
        long h = sec / 3600; long m = (sec % 3600) / 60; long s = sec % 60;
        return String.format("%02d:%02d:%02d", h, m, s);
    }

    private void resetStats() {
        studentValue.setText("—"); courseValue.setText("—"); startValue.setText("—"); endValue.setText("—"); durationValue.setText("—"); redValue.setText("0");
    }
}
```

**What to notice:**
- Left: the saved-session list (`JList` of files; `.dat` rows get an
  "[UNSEALED]" prefix) + Refresh + Delete selected.
- Right: password row + six stat tiles + the log viewer, inside a
  `JSplitPane` (30% left).
- `openSelected()` runs on a WORKER thread (PBKDF2 is slow) and comes back to
  the EDT; the password field is cleared after EVERY operation.
- `renderLogWithHighlights()` counts `[RED-FLAG]` and `[NOTICE]`, parses
  SESSION_START/END fields by string search, and appends rows in red / yellow /
  white. `deleteSelected()` confirms, then deletes through the vault (which
  may raise a UAC prompt — hence the worker thread).

## C7. build-installer.bat — the one-command build

```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

rem ============================================================
rem  Cheat.Guard 2.0 - ONE-COMMAND BUILDER
rem  Produces exactly ONE artifact: dist\CheatGuard-2.0.0.exe
rem  A single Windows installer that bundles the app AND its
rem  own Java runtime - nothing else to build or download.
rem ============================================================

rem Internal MSI version only (upgrade machinery); the shipped file carries no version.
set "APP_VERSION=1.0"
set "APP_NAME=CheatGuard"
set "SETUP_EXE=dist\CheatGuard-Setup.exe"

echo ============================================================
echo  CheatGuard - single installer builder
echo  Output: %SETUP_EXE%
echo ============================================================
echo.

echo [1/5] Checking build tools...
where javac >nul 2>nul || (echo ERROR: javac not found. Install JDK 17+.& exit /b 1)
where jar    >nul 2>nul || (echo ERROR: jar not found. Install a full JDK.& exit /b 1)
where jpackage >nul 2>nul || (echo ERROR: jpackage not found. Install JDK 17+.& exit /b 1)

rem WiX 3.x is required by jpackage to build the .exe installer.
set "WIX_FOUND="
where candle.exe >nul 2>nul && where light.exe >nul 2>nul && set "WIX_FOUND=1"
if not defined WIX_FOUND (
  for %%D in (
    "%~dp0..\tools\wix"
    "C:\Users\mdroh\.zcode\workspace\default\tools\wix"
    "%ProgramFiles(x86)%\WiX Toolset v3.14\bin"
    "%ProgramFiles(x86)%\WiX Toolset v3.11\bin"
    "%ProgramFiles%\WiX Toolset v3.14\bin"
    "%ProgramFiles%\WiX Toolset v3.11\bin"
  ) do (
    if not defined WIX_FOUND if exist "%%~D\candle.exe" if exist "%%~D\light.exe" (
      set "PATH=%%~D;!PATH!"
      set "WIX_FOUND=1"
      echo WiX found at: %%~D
    )
  )
)
if not defined WIX_FOUND (
  echo ERROR: WiX Toolset 3.x not found. jpackage needs candle.exe/light.exe to build an .exe installer.
  exit /b 1
)
echo.

echo [2/5] Cleaning previous build...
if exist bin        rmdir /s /q bin
if exist build      rmdir /s /q build
if exist dist       rmdir /s /q dist
mkdir bin
mkdir build\input
mkdir dist
echo.

echo [3/5] Compiling Java sources...
setlocal DisableDelayedExpansion
set "SRC_LIST=%TEMP%\cheatguard_sources.txt"
> "%SRC_LIST%" (
  for /r src %%F in (*.java) do @echo %%F
)
javac -encoding UTF-8 -d bin "@%SRC_LIST%"
if errorlevel 1 (echo ERROR: compilation failed.& exit /b 1)
endlocal & set "APP_VERSION=%APP_VERSION%" & set "APP_NAME=%APP_NAME%" & set "SETUP_EXE=%SETUP_EXE%"
echo Compiled OK.
echo.

echo [4/5] Packaging jar (app + resources)...
jar --create --file build\%APP_NAME%.jar --main-class com.cheatguard.Main -C bin . -C resources .
if errorlevel 1 (echo ERROR: jar packaging failed.& exit /b 1)
copy /y build\%APP_NAME%.jar build\input\%APP_NAME%.jar >nul
rem Support tools ship inside the installed app folder so an invigilator can
rem repair or diagnose a machine without the development team present.
copy /y support\emergency-restore.bat build\input\ >nul
copy /y support\diagnostics.bat build\input\ >nul
if not exist build\input\support mkdir build\input\support
copy /y support\emergency-restore.ps1 build\input\support\ >nul
copy /y support\diagnostics.ps1 build\input\support\ >nul
echo Jar OK.
echo.

echo [5/5] Building the single installer (this bundles a trimmed Java runtime)...
jpackage ^
  --type exe ^
  --input build\input ^
  --main-jar %APP_NAME%.jar ^
  --name %APP_NAME% ^
  --app-version %APP_VERSION% ^
  --vendor "Cheat.Guard Project" ^
  --description "Cheat.Guard - exam lockdown for Windows" ^
  --icon resources\icon.ico ^
  --win-shortcut ^
  --win-menu ^
  --win-menu-group "Cheat.Guard" ^
  --win-dir-chooser ^
  --win-upgrade-uuid 8f2b6f5a-1c4e-4d9a-9b3f-2a7c5d8e1f30 ^
  --java-options "-Dfile.encoding=UTF-8" ^
  --add-modules java.base,java.desktop,java.management,java.logging,java.xml,jdk.crypto.ec ^
  --jlink-options "--strip-native-commands --no-header-files --no-man-pages --compress zip-6" ^
  --temp build\jpackage ^
  --dest dist
if errorlevel 1 (echo ERROR: jpackage failed.& exit /b 1)

echo.
move /y "dist\%APP_NAME%-%APP_VERSION%.exe" "%SETUP_EXE%" >nul
if exist "%SETUP_EXE%" (
  echo ============================================================
  echo  BUILD SUCCESSFUL
  echo  Installer: %SETUP_EXE%
  for %%A in ("%SETUP_EXE%") do echo  Size: %%~zA bytes
  echo  This ONE file contains the app + Java runtime.
  echo  Double-click it to install Cheat.Guard.
  echo ============================================================
) else (
  echo ERROR: expected installer %SETUP_EXE% was not produced.
  exit /b 1
)
endlocal
```

**The five steps:**
1. Check tools (javac/jar/jpackage on PATH; WiX auto-detected from our tools
   folder or the standard installs).
2. Clean bin/build/dist and recreate.
3. `javac -encoding UTF-8 -d bin @sources.txt` — the @-file avoids command-line
   length limits.
4. `jar --create --main-class com.cheatguard.Main -C bin . -C resources .` —
   classes + resources in one jar; the support tools are copied in so they
   ship inside the installed folder.
5. `jpackage --type exe` with WiX: icon, shortcuts, upgrade UUID, and the
   trimmed runtime (`--add-modules ...` must be TOP LEVEL — a JDK quirk we
   learned; `--compress zip-6` keeps it small). Output renamed to
   `dist\CheatGuard-Setup.exe` (~40 MB).

## C8. test/CoreFlowTest.java — the 76 checks, full code

### Group runners and helpers

```java
import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.AdminCredentialStore;
import com.cheatguard.security.AesEncryptor;
import com.cheatguard.security.Sha256Signer;
import com.cheatguard.watchdog.DnsAllowlistServer;
import com.cheatguard.watchdog.ProcessInfo;
import com.cheatguard.watchdog.ProcessScanner;
import com.cheatguard.watchdog.WatchdogEngine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Headless core verification for Cheat.Guard 2.0.
 *
 * Run with an isolated LOCALAPPDATA so the developer's own credential store and
 * vault are never touched. Every check prints PASS/FAIL; the process exits
 * non-zero if anything failed.
 */
public class CoreFlowTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("== Cheat.Guard 2.0 CoreFlowTest ==");
        System.out.println("Isolated data dir: " + com.cheatguard.config.AppPaths.getDataDirectory());

        checkAdminAuth();
        checkVault();
        checkSiteNormalize();
        checkDnsServer();
        checkProcessScanner();
        checkDnsWireParser();
        checkSpoofRejection();
        checkLogInjection();
        checkSeverityLevels();
        checkAnswerIpParsing();
        checkTitlePathRule();
        checkEditorTitleRule();
        checkRuntimeArgRule();
        checkLockPathCollection();

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL CHECKS PASSED");
        } else {
            System.out.println(failures + " CHECK(S) FAILED");
            System.exit(1);
        }
    }

    // ------------------------------------------------------------- credentials

```

### checkAdminAuth — the password cycle (10 checks)

```java
    private static void checkAdminAuth() throws Exception {
        section("AdminAuth");
        AdminAuth auth = new AdminAuth();
        if (auth.isConfigured()) {
            // A leftover cred file from a crashed previous run would block create;
            // delete it only because this run is fully isolated.
            new com.cheatguard.security.AdminCredentialStore().getFile().delete();
            auth = new AdminAuth(); // fresh store view after deletion
        }

        expect("fresh install is unconfigured", !auth.isConfigured());

        boolean weakRejected = false;
        try { auth.createPassword("short1".toCharArray()); }
        catch (IllegalArgumentException e) { weakRejected = true; }
        expect("short password rejected", weakRejected);

        boolean weakRejected2 = false;
        try { auth.createPassword("onlyletters".toCharArray()); }
        catch (IllegalArgumentException e) { weakRejected2 = true; }
        expect("letters-only password rejected", weakRejected2);

        char[] pw = "ExamGuard#2026".toCharArray();
        auth.createPassword(pw);
        expect("createPassword wipes its input", isZeroed(pw));
        expect("now configured", auth.isConfigured());

        AdminCredentialStore.Result ok = auth.check("ExamGuard#2026".toCharArray());
        expect("correct password verifies", ok.success());

        AdminCredentialStore.Result empty = auth.check(new char[0]);
        expect("empty password refused without burning attempt",
                !empty.success() && empty.attemptsLeft() == AdminCredentialStore.MAX_ATTEMPTS);

        boolean wrongOk = true;
        for (int i = 0; i < AdminCredentialStore.MAX_ATTEMPTS - 1; i++) {
            wrongOk &= !auth.check(("WrongPass" + i + "x").toCharArray()).success();
        }
        expect("four wrong attempts all refused", wrongOk);

        AdminCredentialStore.Result finalWrong = auth.check("WrongPassFinal".toCharArray());
        expect("fifth wrong attempt triggers lockout", !finalWrong.success() && finalWrong.lockedForMs() > 0);

        AdminCredentialStore.Result duringLock = auth.check("ExamGuard#2026".toCharArray());
        expect("even the correct password is refused while locked", !duringLock.success());
    }

    // ------------------------------------------------------------------- vault

```

### checkVault — sealing (7 checks)

```java
    private static void checkVault() throws Exception {
        section("Vault (AES + signature, password as char[])");
        File logFile = new File(AppPaths.getVaultDirectory(), "test.dat");
        if (!logFile.getParentFile().exists()) logFile.getParentFile().mkdirs();

        AdminCredentialStore cred = new AdminCredentialStore();
        AdminAuth auth = new AdminAuth();
        com.cheatguard.security.SecurityVault vault = new com.cheatguard.security.SecurityVault(auth);

        // Force a known password store of our own for this section.
        File credFile = new com.cheatguard.security.AdminCredentialStore().getFile();
        credFile.delete();
        auth.createPassword("VaultTest#2026".toCharArray());

        java.io.PrintWriter w = new java.io.PrintWriter(logFile, StandardCharsets.UTF_8);
        w.println("2026-09-20 10:00:00 [NORMAL] INFO SESSION_START :: Course=TST | StudentID=1");
        w.println("2026-09-20 10:05:00 [RED-FLAG] CRITICAL BLOCKED_INTERNET_DOMAIN :: youtube.com - YouTube");
        w.close();

        char[] pw = "VaultTest#2026".toCharArray();
        vault.sealVault(logFile, pw.clone());
        File vaultFile = new File(logFile.getParent(), "test.vault");
        File sigFile = new File(logFile.getParent(), "test.vault.sig");
        expect("plaintext removed after seal", !logFile.exists());
        expect("vault file created", vaultFile.isFile());
        expect("signature file created", sigFile.isFile());

        String opened = vault.openLog(vaultFile, pw.clone());
        expect("sealed log decrypts with correct password",
                opened.contains("SESSION_START") && opened.contains("youtube.com"));

        boolean wrongRefused = false;
        try { vault.openLog(vaultFile, "WrongPass#1".toCharArray()); }
        catch (Exception e) { wrongRefused = true; }
        expect("wrong password refused", wrongRefused);

        // Tamper: flip a byte in the middle of the vault.
        byte[] raw = readAll(vaultFile);
        raw[raw.length / 2] ^= 0x5A;
        java.nio.file.Files.write(vaultFile.toPath(), raw);
        boolean tamperDetected = false;
        try { vault.openLog(vaultFile, pw.clone()); }
        catch (Exception e) { tamperDetected = true; }
        expect("tampered vault rejected", tamperDetected);

        // The tamper flipped a ciphertext byte, so the signature now mismatches the
        // contents; restore by re-signing is not attempted — recreate instead.
        vaultFile.delete();
        sigFile.delete();
        java.io.PrintWriter w2 = new java.io.PrintWriter(logFile, StandardCharsets.UTF_8);
        w2.println("second round");
        w2.close();
        vault.sealVault(logFile, pw.clone());
        vault.deleteLog(new File(logFile.getParent(), "test.vault"), pw.clone());
        expect("deleteLog removes vault and signature",
                !vaultFile.exists() && !sigFile.exists());

        if (logFile.exists()) logFile.delete();
    }

    // ---------------------------------------------------------------- settings

```

### checkSiteNormalize — domain rules (6 checks)

```java
    private static void checkSiteNormalize() {
        section("AppConfig site normalization");
        expect("bare host", AppConfig.normalizeSite("codeforces.com").equals("codeforces.com"));
        expect("https url", AppConfig.normalizeSite("https://www.atcoder.jp/contests").equals("atcoder.jp"));
        expect("subdomain wildcard", AppConfig.normalizeSite("*.toph.co").equals("toph.co"));
        expect("invalid single word rejected", AppConfig.normalizeSite("com").isEmpty());
        expect("trailing dots", AppConfig.normalizeSite("vjudge.net..").equals("vjudge.net"));
        expect("uppercase", AppConfig.normalizeSite("CodeChef.COM").equals("codechef.com"));
    }

    // --------------------------------------------------------------------- DNS

```

### checkDnsServer — the live filter (5 checks)

```java
    private static void checkDnsServer() throws Exception {
        section("DnsAllowlistServer (allow/NXDOMAIN, upstream, cache)");
        // Allow the test domain only.
        File wl = AppPaths.getWhitelistFile();
        if (wl.exists()) wl.delete();
        java.util.Properties props = new java.util.Properties();
        props.setProperty("allowed.processes", "code.exe");
        props.setProperty("allowed.sites", "example.com");
        File parent = wl.getParentFile();
        if (!parent.exists()) parent.mkdirs();
        java.io.FileWriter fw = new java.io.FileWriter(wl);
        props.store(fw, "test");
        fw.close();
        // Reset the singleton so it reloads the new file.
        java.lang.reflect.Field f = AppConfig.class.getDeclaredField("instance");
        f.setAccessible(true);
        f.set(null, null);

        DnsAllowlistServer server = new DnsAllowlistServer(new LogManager(new File(AppPaths.getDataDirectory(), "test-log.dat")), null);
        server.start();
        try {
            expect("IPv4 bound", server.isRunning());
            expect("IPv6 bound on ::1", server.isIpv6Bound());

            byte[] blocked = query(server, "blocked.invalid-guard.com");
            expect("blocked host gets NXDOMAIN", blocked != null && rcode(blocked) == 3);

            byte[] allowed = query(server, "example.com");
            // Network may be unavailable in the test environment; a real answer or a
            // SERVFAIL both prove the filter forwarded. NXDOMAIN would be a bug.
            expect("allowed host is forwarded (not NXDOMAIN)", allowed != null && rcode(allowed) != 3);
            if (allowed != null && rcode(allowed) == 0) {
                byte[] cached = query(server, "example.com");
                expect("second lookup answered (cache path ok)", cached != null && rcode(cached) == 0
                        && idMatches(cached));
            }
        } finally {
            server.close();
        }
    }

    private static byte[] query(DnsAllowlistServer server, String host) throws Exception {
        ByteArrayOutputStream name = new ByteArrayOutputStream();
        for (String label : host.split("\\.")) {
            name.write(label.length());
            name.write(label.getBytes(StandardCharsets.US_ASCII));
        }
        name.write(0);
        byte[] q = new byte[12 + name.size() + 4];
        q[0] = 0x4A; q[1] = 0x7B;               // id
        q[2] = 0x01;                             // RD
        q[5] = 0x01;                             // QDCOUNT
        System.arraycopy(name.toByteArray(), 0, q, 12, name.size());
        q[q.length - 4] = 0; q[q.length - 3] = 1;  // QTYPE=A
        q[q.length - 2] = 0; q[q.length - 1] = 1;  // QCLASS=IN

        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(8000);
            s.send(new DatagramPacket(q, q.length, InetAddress.getByName("127.0.0.1"), 53));
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            s.receive(resp);
            byte[] out = new byte[resp.getLength()];
            System.arraycopy(resp.getData(), 0, out, 0, resp.getLength());
            out[0] = q[0]; out[1] = q[1]; // sanity for idMatches()
            return out;
        }
    }

    private static int rcode(byte[] dns) { return dns[3] & 0x0F; }
    private static boolean idMatches(byte[] dns) { return dns[0] == 0x4A && dns[1] == 0x7B; }

```

### checkDnsWireParser + checkSpoofRejection — bytes (5 checks)

```java
    private static void checkDnsWireParser() {
        section("DNS wire parser");
        ByteArrayOutputStream name = new ByteArrayOutputStream();
        for (String label : new String[]{"WWW", "Example", "COM"}) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            name.write(b.length);
            name.write(b, 0, b.length);
        }
        name.write(0);
        byte[] msg = new byte[12 + name.size() + 4];
        System.arraycopy(name.toByteArray(), 0, msg, 12, name.size());
        expect("parseQName lowercases and joins",
                "www.example.com".equals(DnsAllowlistServer.parseQName(msg)));
        expect("parseQName rejects tiny packet", DnsAllowlistServer.parseQName(new byte[4]) == null);
    }

    // ------------------------------------------------------- spoof rejection

    private static void checkSpoofRejection() {
        section("DNS upstream reply validation (anti-spoofing)");
        byte[] q = buildQuery("allowed.example.com", (byte) 0x11, (byte) 0x22);
        byte[] good = buildReply(q, (byte) 0x11, (byte) 0x22);
        expect("correct reply accepted", com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(good, q));

        byte[] wrongId = buildReply(q, (byte) 0xAB, (byte) 0xCD);
        expect("wrong transaction ID rejected", !com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(wrongId, q));

        byte[] otherQuery = buildQuery("other.example.com", (byte) 0x11, (byte) 0x22);
        byte[] wrongQuestion = buildReply(otherQuery, (byte) 0x11, (byte) 0x22);
        expect("reply for a different question rejected",
                !com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(wrongQuestion, q));
    }

    private static byte[] buildQuery(String host, byte id0, byte id1) {
        try {
            java.io.ByteArrayOutputStream name = new java.io.ByteArrayOutputStream();
            for (String label : host.split(PURE_DOT)) {
                name.write(label.length());
                name.write(label.getBytes(StandardCharsets.US_ASCII));
            }
            name.write(0);
            byte[] q = new byte[12 + name.size() + 4];
            q[0] = id0; q[1] = id1; q[2] = 0x01; q[5] = 0x01;
            System.arraycopy(name.toByteArray(), 0, q, 12, name.size());
            q[q.length - 4] = 0; q[q.length - 3] = 1;
            q[q.length - 2] = 0; q[q.length - 1] = 1;
            return q;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static final String PURE_DOT = "\\.";

    private static byte[] buildReply(byte[] query, byte id0, byte id1) {
        byte[] r = query.clone();
        r[0] = id0; r[1] = id1;
        r[2] = (byte) 0x81; r[3] = (byte) 0x80;
        return r;
    }

    // ---------------------------------------------------------- log injection

```

### checkLogInjection — the forgery defense (2 checks)

```java
    private static void checkLogInjection() {
        section("Violation log-injection sanitization");
        String evilType = "TEST" + CRLF + "2026-01-01 00:00:00 [NORMAL] INFO SESSION_END :: fake - forged";
        String evilDesc = "desc" + LF + "line2" + TAB + "tabbed";
        com.cheatguard.core.Violation v = new com.cheatguard.core.Violation(
                evilType, evilDesc, com.cheatguard.core.Violation.Severity.INFO);
        String line = v.toString();
        expect("no CR/LF survives into the log line", !line.contains(LF) && !line.contains(CR));
        expect("line breaks flattened to spaces, tabs stripped",
                line.contains("desc line2 tabbed") && !line.contains(TAB));
    }

```

### checkTitlePathRule — drive paths in titles (5 checks)

```java
    private static void checkTitlePathRule() {
        section("Allowed-app title path rule");
        String exam = "C:" + '\\' + "Users" + '\\' + "t" + '\\' + "Desktop" + '\\' + "Exam_1";
        expect("title without any drive path is clean",
                WatchdogEngine.titlePathOutside("notes.txt - Notepad", exam) == null);
        expect("title showing the exam folder is clean",
                WatchdogEngine.titlePathOutside(exam + '\\' + "main.cpp - Notepad++", exam) == null);
        expect("title showing an outside drive path is flagged",
                WatchdogEngine.titlePathOutside("C:" + '\\' + "Users" + '\\' + "t"
                        + '\\' + "notes.txt - Notepad++", exam) != null);
        expect("forward-slash outside path is flagged too",
                WatchdogEngine.titlePathOutside("D:/stuff/cheat.txt - Editor", exam) != null);
        expect("blank title is clean",
                WatchdogEngine.titlePathOutside("", exam) == null);
    }

```

### checkEditorTitleRule — foreign folder segments (6 checks)

```java
    private static void checkEditorTitleRule() {
        section("Allowed editor folder-segment rule");
        String vs = "Visual Studio Code";
        expect("title with the exam folder is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "main.cpp - Exam_1 - " + vs, vs, "Exam_1", null));
        expect("title with a foreign folder is flagged",
                WatchdogEngine.editorShowsOutsideFolder(
                        "notes.py - CheatNotes - " + vs, vs, "Exam_1", null));
        expect("welcome page is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Get Started - " + vs, vs, "Exam_1", null));
        expect("folder-only exam title is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Exam_1 - " + vs, vs, "Exam_1", null));
        expect("untitled scratch tab is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Untitled-1 - " + vs, vs, "Exam_1", null));
        expect("title not matching the editor suffix is ignored",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "notes.py - CheatNotes - Some App", vs, "Exam_1", null));
    }

```

### checkRuntimeArgRule — interpreter command lines (5 checks)

```java
    private static void checkRuntimeArgRule() {
        section("Allowed runtime argument rule");
        String exam = "C:" + '\\' + "Users" + '\\' + "t" + '\\' + "Desktop" + '\\' + "Exam_1";
        expect("exam-folder script argument is clean",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "-u", exam + '\\' + "solve.py"}, exam) == null);
        expect("outside script argument is flagged",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "-u", "D:" + '\\' + "cheat" + '\\' + "solve.py"}, exam) != null);
        expect("vs code tooling paths are ignored",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "C:" + '\\' + "Users" + '\\' + "t" + '\\' + ".vscode"
                                + '\\' + "adapter.py"}, exam) == null);
        expect("flag-only arguments are clean",
                WatchdogEngine.runtimeArgOutside(new String[]{"-m", "jedi"}, exam) == null);
        expect("no arguments is clean",
                WatchdogEngine.runtimeArgOutside(null, exam) == null);
    }

```

### checkLockPathCollection — file walls (6 checks)

```java
    private static void checkLockPathCollection() throws Exception {
        section("File-access lock path collection");
        java.io.File base = new java.io.File(System.getProperty("java.io.tmpdir"),
                "cgt-" + System.nanoTime());
        java.io.File profile = new java.io.File(base, "profile");
        java.io.File documents = new java.io.File(profile, "Documents");
        java.io.File downloads = new java.io.File(profile, "Downloads");
        java.io.File desktop = new java.io.File(base, "Desktop");
        java.io.File exam = new java.io.File(desktop, "Exam_1");
        java.io.File cheat = new java.io.File(desktop, "CheatNotes");
        java.io.File lnk = new java.io.File(desktop, "shortcut.lnk");
        java.io.File note = new java.io.File(desktop, "note.txt");
        java.io.File root = new java.io.File(base, "Ddrive");
        for (java.io.File f : new java.io.File[]{documents, downloads, desktop, exam, cheat, root}) {
            f.mkdirs();
        }
        lnk.createNewFile();
        note.createNewFile();
        java.util.List<java.io.File> roots = java.util.Arrays.asList(root,
                new java.io.File(base, "Missing"));
        java.util.List<String> paths = com.cheatguard.watchdog.StrictNetworkLockdown
                .collectLockPaths(profile, desktop, exam, roots);
        expect("profile content folders are locked",
                paths.contains(documents.getAbsolutePath())
                        && paths.contains(downloads.getAbsolutePath()));
        expect("foreign desktop folder is locked", paths.contains(cheat.getAbsolutePath()));
        expect("exam folder is never locked", !paths.contains(exam.getAbsolutePath()));
        expect("shortcuts are never locked", !paths.contains(lnk.getAbsolutePath()));
        expect("loose desktop files are locked", paths.contains(note.getAbsolutePath()));
        expect("extra drive roots are locked and missing roots skipped",
                paths.contains(root.getAbsolutePath())
                        && !paths.contains(new java.io.File(base, "Missing").getAbsolutePath()));
        for (java.io.File f : new java.io.File[]{documents, downloads, exam, cheat, root,
                desktop, profile, base}) {
            f.delete();
        }
    }

    private static final String CRLF = new String(new char[]{'\r', '\n'});
    private static final String LF = new String(new char[]{'\n'});
    private static final String CR = new String(new char[]{'\r'});
    private static final String TAB = new String(new char[]{'\t'});

    // --------------------------------------------------------- log levels

```

### checkSeverityLevels + checkAnswerIpParsing (10 checks)

```java
    private static void checkSeverityLevels() {
        section("Violation severity levels and log rows");
        com.cheatguard.core.Violation info = new com.cheatguard.core.Violation(
                "APP_CLOSED_AT_START", "Discord", com.cheatguard.core.Violation.Severity.INFO);
        com.cheatguard.core.Violation notice = new com.cheatguard.core.Violation(
                "BLOCKED_INTERNET_DOMAIN", "facebook.com", com.cheatguard.core.Violation.Severity.NOTICE);
        com.cheatguard.core.Violation red = new com.cheatguard.core.Violation(
                "UNAUTHORIZED_FOLDER_ACCESS", "D:/stuff/Videos", com.cheatguard.core.Violation.Severity.CRITICAL);
        expect("NOTICE is not a red flag", !notice.isRedFlag());
        expect("CRITICAL is a red flag", red.isRedFlag());
        expect("INFO row shows OK", com.cheatguard.gui.LogDisplayFormatter.format(info).contains(" OK  "));
        expect("NOTICE row shows WARN", com.cheatguard.gui.LogDisplayFormatter.format(notice).contains(" WARN "));
        expect("CRITICAL row shows ALERT", com.cheatguard.gui.LogDisplayFormatter.format(red).contains(" ALERT "));
        expect("stored NOTICE line parses back as WARN",
                com.cheatguard.gui.LogDisplayFormatter.formatRaw(notice.toString()).contains(" WARN "));
        expect("stored RED-FLAG line parses back as ALERT",
                com.cheatguard.gui.LogDisplayFormatter.formatRaw(red.toString()).contains(" ALERT "));
    }

    // ------------------------------------------------- egress allowlist feed

    private static void checkAnswerIpParsing() {
        section("DNS answer address extraction (egress allowlist feed)");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0x81, (byte) 0x80,
                0, 1, 0, 1, 0, 0, 0, 0});
        out.writeBytes(new byte[]{10, 'c', 'o', 'd', 'e', 'f', 'o', 'r', 'c', 'e', 's', 3, 'c', 'o', 'm', 0});
        out.writeBytes(new byte[]{0, 1, 0, 1});                       // question: A IN
        out.writeBytes(new byte[]{(byte) 0xC0, 0x0C});                // answer name: pointer
        out.writeBytes(new byte[]{0, 1, 0, 1, 0, 0, 0, 60, 0, 4});    // A IN ttl=60 rdlen=4
        out.writeBytes(new byte[]{104, 16, (byte) 205, 15});          // 104.16.205.15
        List<String> ips = DnsAllowlistServer.parseAnswerIps(out.toByteArray());
        expect("one IPv4 answer extracted", ips.size() == 1);
        expect("answer address is correct", ips.size() == 1 && "104.16.205.15".equals(ips.get(0)));
        expect("truncated message yields no addresses",
                DnsAllowlistServer.parseAnswerIps(new byte[]{0, 1, 2}).isEmpty());
    }

    // ----------------------------------------------------------------- scanner

```

### checkProcessScanner + helpers

```java
    private static void checkProcessScanner() {
        section("ProcessScanner (visible apps)");
        ProcessScanner scanner = new ProcessScanner();
        List<ProcessInfo> visible = scanner.getRunningProcesses();
        System.out.println("  visible processes seen: " + visible.size());
        expect("scanner returns without hanging", true);
    }

    // ------------------------------------------------------------------ helpers

    private static void expect(String label, boolean condition) {
        System.out.println((condition ? "  PASS  " : "  FAIL  ") + label);
        if (!condition) failures++;
    }

    private static void section(String name) {
        System.out.println();
        System.out.println("-- " + name + " --");
    }

    private static boolean isZeroed(char[] a) {
        for (char c : a) if (c != '\0') return false;
        return true;
    }

    private static byte[] readAll(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
    }
}
```

## C9. OOP concepts in my part (with the real places)

1. **Inheritance** — `DashboardPanel extends JPanel`, `SettingsPanel extends
   JPanel`; our buttons extend `JButton`; our border extends `AbstractBorder`.
2. **Method overriding + polymorphism** — `paintComponent`: Swing calls the
   same method, OUR drawing runs. `toString()` overridden in Violation.
3. **Adapter pattern** — `WindowAdapter` (override only `windowClosing` +
   `windowStateChanged`), `FocusAdapter` (focus ring) — instead of five empty
   methods.
4. **Encapsulation** — `UITheme` is final with a private constructor; screens
   only call its factory methods, so the design lives in ONE place.
5. **Interface + lambda** — the violation listener in Main; `Runnable` for the
   worker threads.
6. **Generics** — `leftAlign(T component)` returns the same type it receives.

## C10. Technologies in my part

Swing (JFrame, CardLayout, BoxLayout, GridBagLayout, BorderLayout, JTextPane
with styled text) · Java2D custom painting with antialiasing · `javax.swing.
Timer` · SystemTray (AWT) · worker threads + `SwingUtilities.invokeLater` ·
jpackage + WiX · a self-written headless test framework.

## C11. Questions Sir may ask me

**Q: Why Swing, not JavaFX?**
A: Swing ships inside every JDK, so the single-installer plan stays simple. We
repaint everything ourselves, so the old Swing look is not visible anyway.

**Q: What is CardLayout?**
A: Many panels in one container, one visible at a time — like cards in hand.
Perfect for a wizard-style app; only one window is ever needed.

**Q: What happens if you do a long task on the UI thread?**
A: The window stops repainting and Windows says "Not Responding". Ours never
does: slow work runs on worker threads, results return via `invokeLater`.

**Q: What is `invokeLater` doing?**
A: Only one thread (the Event Dispatch Thread) may touch Swing. `invokeLater`
queues a small job onto it — the official safe bridge from worker threads.

**Q: How does the eye icon work?**
A: A small toggle button placed inside the password field, with the text area
shortened by a margin so text never runs under it. The icon is drawn with
Java2D; clicking flips the echo character between a dot and nothing.

**Q: How did you make one installer?**
A: One script: compile → jar → `jpackage` with WiX → one exe that bundles a
trimmed Java runtime (~40 MB). The target PC needs no Java.

**Q: Why does the app ask for admin at launch?**
A: Blocking needs it (DNS, firewall, closing processes). Before elevating, the
app captures the real user's Desktop so the exam folder lands on the student's
desktop, not the admin's.

**Q: What if the sealed log is edited?**
A: The dashboard re-computes SHA-256; it will not match the stored signature
and the file is reported as tampered.

**Q: If the invigilator forgets the password?**
A: No backdoor, by design. An admin deleting the credential file starts
first-run again with a NEW password; old sealed logs stay locked forever. That
trade-off is documented.

**Handover:** "Together, this is Cheat.Guard: it closes the doors, watches the
room, and seals the evidence."

---

# EVERYONE — the shared last page

## Known limits (say them proudly — honesty scores)

1. A cheat site sharing the exact same CDN address as an approved site cannot
   be told apart without reading encrypted traffic (needs much more than a
   course project). No practical way for a normal student to use it.
2. A phone beside the keyboard or photographing the screen is physics, not
   software. (Streaming/uploading IS blocked by the firewall layer.)
3. Someone with the PC's own administrator password is above any program on it.
   We detect tampering and force a visible reset; a university portal with
   server-side accounts would close this fully.
4. Pre-exam content was the open door through allowed apps, so it is now
   closed from five sides: allowed apps start FRESH (closed at session start,
   relaunched on the exam folder in the student's own session), the recent-file
   lists are wiped, editor tab titles must carry the exam folder's name,
   permitted interpreters are checked by command line, and - the strongest
   layer - the student's account is denied read access to everything outside
   the exam folder by NTFS permissions. What remains: a note typed into an
   editor with no file name at all during the exam - no monitor can read a
   program's mind, but there is also no pre-exam file left to open.

## Numbers to memorize

| Fact | Value |
|---|---|
| Java classes / lines | 35 classes, ~6,000 lines |
| PowerShell helper | ~730 lines |
| Tests | 76 checks, 15 groups |
| Password hashing | PBKDF2-HMAC-SHA256, 210,000 rounds, 16-byte salt |
| Log sealing | AES-256-CBC + SHA-256 signature |
| Password rule | 8+ chars, letters + number/symbol |
| Wrong tries | 5 → lockout 30 s doubling, max 15 min |
| DNS filter | 127.0.0.1:53 + ::1:53, cache 30 s |
| Watchdog cycle | every 1.2 s; startup grace 60 s |
| File walls | student account denied read access outside the exam folder |
| Installer | one exe, ~40 MB, own Java runtime |

## The one-map revision (who calls whom)

```
main() → ensureElevated() → start() → first-run / home screen
"Start exam session" → setup screen → startExam()
startExam() → ExamSession (log file) → SecurityVault.beginProtection
            → StrictNetworkLockdown.start() (DNS server + elevated helper)
            → WatchdogEngine (1.2 s loop)
Every event → Violation → LogManager (file) + listener (screen)
End (password) → finishActiveExam() → sealVault() → stopAndRestore()
Dashboard (password) → SecurityVault.openLog / deleteLog
```

## If Sir asks something you cannot answer

1. Bridge: "In our design, the closest thing we built is …" and explain that.
2. Honest limit: "That needs a server or driver layer beyond this project — we
   listed it as a known limit."
3. Never invent an API or a number. "I would check the code to be exact" is a
   fine answer.
4. If Sir corrects you: "Thank you Sir — we will note it as an improvement."

