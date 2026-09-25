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
import java.util.Set;
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
