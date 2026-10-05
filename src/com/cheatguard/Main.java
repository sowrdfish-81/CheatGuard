package com.cheatguard;

import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.gui.fx.CheatGuardFxApp;
import com.cheatguard.gui.fx.SessionUi;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.AdminCredentialStore;
import com.cheatguard.security.InstanceGuard;
import com.cheatguard.security.LogProtection;
import com.cheatguard.security.SecurityVault;
import com.cheatguard.watchdog.SessionEnvironment;
import com.cheatguard.watchdog.StrictNetworkLockdown;
import com.cheatguard.watchdog.ViolationListener;
import com.cheatguard.watchdog.WatchdogEngine;

import javafx.application.Application;
import javafx.application.Platform;

import javax.swing.JOptionPane;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Cheat.Guard — exam lockdown with a DNS-enforced website allowlist.
 *
 * <p>This class is the CONTROLLER: it owns the session lifecycle, the security
 * objects and the elevation/instance machinery, and never touches a widget. All
 * interface work lives in {@code com.cheatguard.gui.fx} (JavaFX); the two layers
 * talk through the {@link SessionUi} callback interface. Every long-running
 * operation (network lockdown, vault sealing, log deletion) runs on a worker
 * thread and reports back on the JavaFX thread: the UAC prompt, the elevated
 * helper handshake and the PBKDF2 key derivations each take seconds, and
 * freezing the interface during an exam makes Windows mark the window as
 * "Not Responding" — alarming for the invigilator and an invitation to
 * task-kill the app.
 */
public class Main {

    /** Visible in the window title, so "which build am I running" is never a guess. */
    public static final String BUILD_STAMP = "2026-10-06 04:20";

    private static final InstanceGuard INSTANCE_GUARD = new InstanceGuard();

    private final AdminAuth adminAuth = new AdminAuth();
    private final SessionEnvironment sessionEnvironment = new SessionEnvironment();

    private ExamSession activeSession;
    private SecurityVault activeSecurityVault;
    private WatchdogEngine activeWatchdog;
    private Thread activeWatchdogThread;
    private StrictNetworkLockdown activeNetworkLockdown;
    /** Guards double-clicks while a session is being started or ended. */
    private volatile boolean sessionBusy;

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

        UIThemelessLookAndFeels();
        if (!INSTANCE_GUARD.acquire()) {
            JOptionPane.showMessageDialog(null,
                    "Cheat.Guard is already running. Close the existing window first.",
                    "Already running", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(INSTANCE_GUARD::close, "InstanceGuard-Release"));
        // One-time per scan-version: find every compiler/tool installed on THIS
        // machine (gcc, git, flex, java, python...) and allow it with its path.
        com.cheatguard.config.ToolchainScanner.scanIfNeededAsync();
        if (!StrictNetworkLockdown.recoverStaleIfPresent()) {
            JOptionPane.showMessageDialog(null,
                    "A previous exam session could not be restored automatically.\n"
                            + "Ask the administrator to restore the network from\n"
                            + AppPaths.getNetworkDirectory().getAbsolutePath()
                            + " with an elevated PowerShell, then start Cheat.Guard again.",
                    "Network recovery required", JOptionPane.ERROR_MESSAGE);
            INSTANCE_GUARD.close();
            return;
        }
        // Hand over to the JavaFX interface; Application.launch blocks until the
        // window closes and then the process exits through the FX thread.
        Application.launch(CheatGuardFxApp.class, args);
    }

    /** Swing dialogs only for the rare pre-UI error paths (no FX stage exists yet). */
    private static void UIThemelessLookAndFeels() {
        try {
            javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
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
            File desktopNow = AppPaths.getDesktopDirectory();
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

    // ------------------------------------------------------- instance surface

    public AdminAuth adminAuth() { return adminAuth; }
    public boolean sessionBusy() { return sessionBusy; }
    public ExamSession activeSession() { return activeSession; }

    /** A stored credential that failed its integrity check cannot be trusted. */
    public boolean isCredentialTampered() { return adminAuth.isTampered(); }
    public void discardRejectedCredential() { adminAuth.discardRejectedCredential(); }

    /** Human text for a refused verification, including throttling. */
    public String verificationProblem(AdminCredentialStore.Result r) {
        if (!r.configured()) {
            return "No administrator password is set on this computer.";
        }
        if (r.lockedForMs() > 0) {
            long seconds = Math.max(1, r.lockedForMs() / 1000);
            return "Too many incorrect attempts. Try again in " + seconds + " seconds.";
        }
        return r.attemptsLeft() >= AdminCredentialStore.MAX_ATTEMPTS
                ? "Enter the administrator password."
                : "Incorrect password. " + r.attemptsLeft() + " attempt(s) left before a lockout.";
    }

    // ------------------------------------------------------- session lifecycle

    /**
     * Begin the exam session. The elevated helper handshake (UAC + ready marker)
     * can take up to 90 seconds; all of it happens off the interface thread and
     * the outcome is reported through {@code ui}.
     */
    public void startExam(SessionUi ui, String course, String studentId) {
        if (sessionBusy) return;
        sessionBusy = true;

        // Session record and log protection are quick and local; they happen here so
        // the monitor screen exists the moment the slow, elevated steps begin.
        activeSession = new ExamSession(course, studentId);
        activeSecurityVault = new SecurityVault(adminAuth);
        activeSecurityVault.beginProtection(activeSession.getSessionFile());

        ExamSession session = activeSession;
        ui.showStarting(session);
        for (Violation v : session.getLogManager().getAllViolations()) ui.onViolation(v);

        // Startup rows (closed apps, file-wall setup, one failed close inside the
        // sweep...) are recorded in the sealed log but NOT shown or counted: the
        // first 30 seconds are the machine settling down, not the student.
        ViolationListener liveListener = violation -> {
            if (activeSession == null) return;
            if (hiddenDuringStartup(session, violation)) return;
            ui.onViolation(violation);
        };

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
            Platform.runLater(() -> {
                if (started) {
                    activeNetworkLockdown = finalLockdown;
                    activeWatchdog = new WatchdogEngine(activeSession.getLogManager(),
                            activeSession.getExamFolder(), liveListener);
                    activeWatchdogThread = new Thread(activeWatchdog, "CheatGuard-Watchdog");
                    activeWatchdogThread.setDaemon(true);
                    activeWatchdogThread.start();
                    ui.showActive(session);
                } else {
                    ui.showStartFailure(finalLockdown.getLastError());
                    activeSession = null;
                    activeSecurityVault = null;
                    activeNetworkLockdown = null;
                    ui.showHome();
                }
                sessionBusy = false;
            });
        }, "CheatGuard-SessionStarter");
        starter.setDaemon(true);
        starter.start();
    }

    /**
     * Ask for the administrator password (the UI collects it), verify it, then run
     * the teardown on a worker thread: sealing derives two PBKDF2 keys, the
     * permission hardening can wait up to 20 seconds for the elevated helper, and
     * restoring the network up to 60 more. None of that may run on the interface
     * thread.
     */
    public void requestEndSession(SessionUi ui, ExamSession session, char[] password) {
        if (sessionBusy) return;
        sessionBusy = true;
        Thread ender = new Thread(() -> {
            boolean sealed = false;
            try {
                sealed = finishActiveExam(password, ui);
            } finally {
                Arrays.fill(password, '\0');
            }
            final boolean done = sealed;
            final long alerts = session == null || session.getLogManager() == null
                    ? 0 : session.getLogManager().getRedFlagCount();
            Platform.runLater(() -> {
                if (done) ui.showSessionComplete(sessionSummary(session, alerts));
                sessionBusy = false;
            });
        }, "CheatGuard-SessionEnder");
        ender.setDaemon(true);
        ender.start();
    }

    private boolean finishActiveExam(char[] password, SessionUi ui) {
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
            Platform.runLater(() -> ui.showSealError(ex.getMessage()));
            return false;
        } finally {
            // Always give the computer its network and clipboard settings back, even if
            // sealing failed - a student must never be left without Internet.
            StrictNetworkLockdown lockdown = activeNetworkLockdown;
            activeNetworkLockdown = null;
            if (lockdown != null && !lockdown.stopAndRestore()) {
                Platform.runLater(ui::showRestoreWarning);
            }
            sessionEnvironment.restore();
            activeSession = null;
            activeSecurityVault = null;
            activeWatchdog = null;
            activeWatchdogThread = null;
        }
    }

    /** Short closing summary so the invigilator sees the outcome without opening the log. */
    public String sessionSummary(ExamSession session, long alerts) {
        String outcome = alerts == 0
                ? "No alerts were raised during this session."
                : alerts + " alert(s) were raised — open the session dashboard to review them.";
        return "Session sealed for student " + session.getStudentId()
                + " (" + session.getCourseCode() + ").\n\n"
                + outcome + "\n\n"
                + "The sealed log is protected: it cannot be deleted from Windows Explorer,\n"
                + "only from the dashboard with the administrator password.";
    }

    /**
     * Window-close path. Called AFTER the UI collected the exit password (or with
     * null when no password is needed). Requests the teardown for a live session
     * and reports {@link SessionUi#allowClose()} when the process may exit.
     */
    public void requestExit(SessionUi ui, char[] entered) {
        if (entered == null) {
            ui.allowClose();
            return;
        }
        if (entered.length == 0) {
            Arrays.fill(entered, '\0');
            ui.showExitMessage("Enter the administrator password.");
            return;
        }
        AdminCredentialStore.Result r = adminAuth.check(entered.clone());
        if (!r.success()) {
            Arrays.fill(entered, '\0');
            ui.showExitMessage(verificationProblem(r));
            return;
        }
        if (activeSession != null) {
            if (sessionBusy) {
                Arrays.fill(entered, '\0');
                ui.showExitMessage("A session action is already in progress.");
                return;
            }
            sessionBusy = true;
            char[] password = entered;
            Thread ender = new Thread(() -> {
                boolean sealed = false;
                try {
                    sealed = finishActiveExam(password, ui);
                } finally {
                    Arrays.fill(password, '\0');
                    // Leave the app open when sealing failed: the unsealed log and the
                    // session summary dialog are still on screen, and the invigilator
                    // can simply press End session again to retry.
                    final boolean done = sealed;
                    Platform.runLater(() -> {
                        if (done) ui.allowClose();
                        else sessionBusy = false;
                    });
                }
            }, "CheatGuard-ExitEnder");
            ender.setDaemon(true);
            ender.start();
            return;
        }
        Arrays.fill(entered, '\0');
        ui.allowClose();
    }

    /**
     * Awareness row for a known bypass path: a second local account already on the
     * machine. The elevated helper hides fast user switching for the session; the
     * row tells the invigilator the accounts exist in the first place.
     */
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

    // -------------------------------------------------------------- first run

    /** Runs once, off the FX thread, after the window is visible. */
    public void postStartupMaintenance() {
        Thread t = new Thread(() -> {
            AppPaths.migrateLegacyProfileData();
            maybeCreateDesktopShortcut();
        }, "CheatGuard-FirstRun");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Create the desktop shortcut once, on the first run after installation. The
     * MSI places a Start Menu entry; invigilators expect the icon on the Desktop
     * too. Best effort only — a failure here must never block the app.
     */
    private void maybeCreateDesktopShortcut() {
        File marker = new File(AppPaths.getDataDirectory(), "shortcut.created");
        if (marker.exists()) return;
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
    }
}
