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
            if (controller.terminate(ph.pid())) {
                emit(new Violation("APP_CLOSED_AT_START", app, Violation.Severity.INFO));
            } else {
                emit(new Violation("UNAUTHORIZED_APP_CLOSE_FAILED", app, Violation.Severity.CRITICAL));
            }
        }
    }

    /** Every process alive when monitoring starts is baseline, whichever session it sits in. */
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

            boolean closed = controller.terminate(ph.pid());
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
            if (seg.startsWith("\u25CF")) seg = seg.substring(1).trim(); // VS Code dirty dot
            if (seg.equalsIgnoreCase(examFolderName)) return false;      // exam folder open
            if (examFolderDir != null && new File(examFolderDir, seg).isFile()) return false;
            if (seg.isEmpty() || BENIGN_EDITOR_TABS.contains(seg.toLowerCase(Locale.ROOT))
                    || seg.toLowerCase(Locale.ROOT).startsWith("untitled")) continue;
            suspicious = true;
        }
        return suspicious;
    }

    private void checkProcesses() {
        List<ProcessInfo> visible = scanner.getRunningProcesses();
        Set<Long> stillVisibleBlocked = new HashSet<>();
        for (ProcessInfo proc : visible) {
            if (proc.getPid() == selfPid) continue;
            if (whitelist.isSystemProcess(proc.getName())) continue; // Windows component: never logged

            // An ALLOWED app is only allowed to work on the exam folder. A drive
            // path outside it in the window title (a file it has open) closes the
            // app; an editor showing a foreign folder raises a red alert.
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

            boolean closed = controller.terminate(proc.getPid());
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
