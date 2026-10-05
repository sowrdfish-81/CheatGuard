package com.cheatguard.gui.fx;

import com.cheatguard.Main;
import com.cheatguard.config.AppConfig;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.gui.LogDisplayFormatter;
import com.cheatguard.security.AdminCredentialStore;
import com.cheatguard.watchdog.AllowedAppLauncher;
import com.cheatguard.watchdog.ProcessWhitelist;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.awt.Desktop;
import java.awt.Rectangle;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

import javax.imageio.ImageIO;

/**
 * The JavaFX interface: one stage, one StackPane of cards, styled entirely from
 * fx-theme.css. Owns navigation, the monitor screen and the system tray, and
 * delegates every action to the {@link Main} controller through {@link SessionUi}.
 */
public class CheatGuardFxApp extends Application implements SessionUi {

    private final Main controller = new Main();
    private Stage stage;
    private StackPane root;
    private Node homeCard;
    private FxMonitorCard monitor;
    private TrayIcon trayIcon;
    private boolean trayHintShown;

    private static Stage primaryStage;

    /** Primary stage for dialogs opened from nested views. */
    public static Stage primaryStage() { return primaryStage; }

    /** One-liner informational dialog for nested views. */
    public static void dialog(String body) {
        FxDialogs.message(primaryStage, "Cheat.Guard", "Cheat.Guard", body, FxDialogs.Kind.INFO);
    }

    @Override
    public void start(Stage stage) {
        FxTheme.load();
        this.stage = stage;
        primaryStage = stage;

        root = new StackPane();
        Scene scene = new Scene(root, 1120, 720);
        scene.getStylesheets().add(getClass().getResource("/fx-theme.css").toExternalForm());
        stage.setTitle("Cheat.Guard — build " + Main.BUILD_STAMP);
        stage.getIcons().addAll(FxTheme.appIcons());
        stage.setMinWidth(980);
        stage.setMinHeight(660);
        stage.setScene(scene);

        if (controller.isCredentialTampered()) {
            FxDialogs.message(stage, "Credential rejected", "Stored credential rejected",
                    "The stored administrator credential does not belong to this computer and was rejected.\n"
                            + "Set a new administrator password to continue.", FxDialogs.Kind.WARN);
            controller.discardRejectedCredential();
        }
        if (!controller.adminAuth().isConfigured()) showCard(buildFirstRunCard());
        else showCard(buildHomeCard());

        setupTray();
        stage.setOnCloseRequest(e -> {
            e.consume();
            handleWindowClose();
        });
        stage.show();
        controller.postStartupMaintenance();

        // Development hook: "--fxshot <dir>" walks the cards, screenshots each and exits.
        List<String> params = getParameters().getUnnamed();
        if (params.size() >= 2 && params.contains("--fxshot")) {
            takeScreenshots(params.get(params.indexOf("--fxshot") + 1));
        }
    }

    // ---------------------------------------------------------------- cards --

    private void showCard(Node card) {
        root.getChildren().setAll(card);
    }

    private void showHomeCard() {
        showCard(homeCard != null ? homeCard : buildHomeCard());
    }

    private Node buildFirstRunCard() {
        VBox card = columnCard(34, 40);

        PasswordField first = new PasswordField();
        first.setPromptText("New password");
        first.setMaxWidth(420);
        PasswordField second = new PasswordField();
        second.setPromptText("Repeat password");
        second.setMaxWidth(420);

        Label error = new Label(" ");
        error.getStyleClass().add("text-danger");
        error.setWrapText(true);

        Button save = pill("Create password and continue", "button-primary");
        save.setMaxWidth(420);

        Runnable doSave = save::fire;
        first.setOnAction(e -> doSave.run());
        second.setOnAction(e -> doSave.run());
        save.setOnAction(e -> {
            char[] a = first.getText().toCharArray();
            char[] b = second.getText().toCharArray();
            try {
                if (a.length == 0) { error.setText("Choose a password first."); return; }
                if (!Arrays.equals(a, b)) { error.setText("The two passwords do not match."); return; }
                controller.adminAuth().createPassword(a);
                homeCard = buildHomeCard();
                showCard(homeCard);
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

        card.getChildren().setAll(
                brandMark(300),
                gap(20),
                heading("Set the administrator password"),
                muted("This password protects settings, the session dashboard and sealed logs."),
                muted("At least 8 characters, mixing letters with a number or symbol. It is never stored as text."),
                gap(22),
                captioned("New password", first),
                gap(14),
                captioned("Repeat password", second),
                gap(22),
                save,
                gap(10),
                error);
        Platform.runLater(first::requestFocus);
        return centered(card);
    }

    private Node buildHomeCard() {
        VBox card = columnCard(38, 54);

        Button startBtn = pill("Start exam session", "button-primary");
        Button dashboardBtn = pill("Session dashboard", "button-secondary");
        Button settingsBtn = pill("Allowed apps and websites", "button-secondary");
        Button exitBtn = pill("Exit", "button-ghost");
        for (Button b : new Button[]{startBtn, dashboardBtn, settingsBtn, exitBtn}) b.setMaxWidth(380);

        startBtn.setOnAction(e -> {
            if (controller.sessionBusy()) return;
            showCard(buildSetupCard());
        });
        dashboardBtn.setOnAction(e -> openDashboard());
        settingsBtn.setOnAction(e -> openSettings());
        exitBtn.setOnAction(e -> handleWindowClose());

        card.getChildren().setAll(
                brandMark(360),
                gap(14),
                muted("Exam lockdown for Windows — website allowlist, app control and sealed audit logs"),
                gap(30),
                startBtn, gap(11), dashboardBtn, gap(11), settingsBtn, gap(20), exitBtn);
        homeCard = centered(card);
        return homeCard;
    }

    private Node buildSetupCard() {
        VBox card = columnCard(34, 44);

        TextField courseField = new TextField();
        courseField.setPromptText("e.g. CSE-3202");
        courseField.setMaxWidth(420);
        TextField studentField = new TextField();
        studentField.setPromptText("e.g. 2021831045");
        studentField.setMaxWidth(420);

        Button startBtn = pill("Start monitoring", "button-primary");
        startBtn.setMaxWidth(420);
        Button backBtn = pill("Back", "button-ghost");
        backBtn.setMaxWidth(420);

        Runnable doStart = () -> {
            String course = courseField.getText().trim();
            String student = studentField.getText().trim();
            if (course.isEmpty() || student.isEmpty()) {
                FxDialogs.message(stage, "Missing details", "Missing details",
                        "Enter both the course code and the student ID.", FxDialogs.Kind.WARN);
                return;
            }
            if (AppConfig.getInstance().getAllowedSites().isEmpty()) {
                boolean go = FxDialogs.confirm(stage, "No approved websites", "No approved websites",
                        "No approved website has been configured.\n"
                                + "During the session EVERY website will fail to open,\n"
                                + "including the exam platform itself.\n\n"
                                + "Start the session anyway?", FxDialogs.Kind.WARN);
                if (!go) return;
            }
            FxDialogs.message(stage, "Starting website lock", "Starting website lock",
                    "Windows will ask for administrator permission next — click Yes.\n\n"
                            + "During the session only the approved websites can be reached, and open browsers\n"
                            + "are restarted once so the new rules apply.", FxDialogs.Kind.INFO);
            // The controller creates the session and calls back showStarting(session),
            // which builds the monitor screen around that exact session.
            controller.startExam(this, course, student);
        };
        startBtn.setOnAction(e -> doStart.run());
        backBtn.setOnAction(e -> showHome());
        courseField.setOnAction(e -> doStart.run());
        studentField.setOnAction(e -> doStart.run());

        card.getChildren().setAll(
                heading("New exam session"),
                muted("A Desktop folder named Exam_<StudentID> is created for the student's work."),
                muted("Browsers are closed when the session starts, so ask the student to save first."),
                gap(24),
                captioned("Course code", courseField),
                gap(14),
                captioned("Student ID", studentField),
                gap(24),
                startBtn,
                gap(10),
                backBtn);
        Platform.runLater(courseField::requestFocus);
        return centered(card);
    }

    // ------------------------------------------------- monitor (SessionUi) --

    @Override
    public void showStarting(ExamSession session) {
        if (Platform.isFxApplicationThread()) {
            monitor = new FxMonitorCard(this, session, true);
            showCard(monitor.getNode());
        } else {
            Platform.runLater(() -> {
                monitor = new FxMonitorCard(this, session, true);
                showCard(monitor.getNode());
            });
        }
    }

    @Override
    public void showActive(ExamSession session) {
        Platform.runLater(() -> {
            if (monitor != null) monitor.setActive();
            showCard(monitor != null ? monitor.getNode() : buildHomeCard());
        });
    }

    @Override
    public void onViolation(Violation violation) {
        Platform.runLater(() -> {
            if (monitor != null) monitor.append(violation);
        });
    }

    @Override
    public void showStartFailure(String detail) {
        Platform.runLater(() -> {
            String text = detail == null || detail.isBlank() ? "Windows did not report a reason." : detail;
            FxDialogs.message(stage, "Could not start the session", "Could not start the session",
                    "The website lock could not be enabled, so the exam was NOT started.\n"
                            + "Nothing on this computer was left changed.\n\nWindows reported:\n" + text,
                    FxDialogs.Kind.ERROR);
        });
    }

    @Override
    public void showSessionComplete(String summary) {
        Platform.runLater(() -> {
            FxDialogs.message(stage, "Session complete", "Session complete", summary, FxDialogs.Kind.INFO);
            showHome();
        });
    }

    @Override
    public void showRestoreWarning() {
        Platform.runLater(() -> FxDialogs.message(stage, "Network restore warning", "Network restore warning",
                "Windows did not confirm that the network settings were restored.\n"
                        + "If the Internet stays blocked, start Cheat.Guard again —\n"
                        + "it offers to repair a leftover lockdown automatically —\n"
                        + "or ask an administrator to restore the network from the\n"
                        + "network folder under ProgramData.",
                FxDialogs.Kind.WARN));
    }

    @Override
    public void showSealError(String message) {
        Platform.runLater(() -> FxDialogs.message(stage, "Error", "Could not seal the session log",
                message == null ? "Unknown error." : message, FxDialogs.Kind.ERROR));
    }

    @Override
    public void showExitMessage(String message) {
        Platform.runLater(() -> FxDialogs.message(stage, "Cheat.Guard", "Cheat.Guard", message, FxDialogs.Kind.INFO));
    }

    @Override
    public void allowClose() {
        Platform.runLater(() -> {
            removeTray();
            Platform.exit();
        });
    }

    @Override
    public void showHome() {
        Platform.runLater(this::showHomeCard);
    }

    // --------------------------------------------------------- window close --

    private void handleWindowClose() {
        if (!controller.adminAuth().isConfigured()) {
            controller.requestExit(this, null);
            return;
        }
        char[] entered = FxDialogs.password(stage,
                controller.activeSession() == null ? "Exit Cheat.Guard" : "End session and exit");
        if (entered == null) return;
        controller.requestExit(this, entered);
    }

    // --------------------------------------------------- admin-gated screens --

    private void openDashboard() {
        char[] password = FxDialogs.password(stage, "Open session dashboard");
        if (password == null) return;
        AdminCredentialStore.Result r = controller.adminAuth().check(password.clone());
        if (!r.success()) {
            Arrays.fill(password, '\0');
            FxDialogs.message(stage, "Access denied", "Access denied",
                    controller.verificationProblem(r), FxDialogs.Kind.ERROR);
            return;
        }
        showCard(new FxDashboard(controller, password, () -> {
            Arrays.fill(password, '\0'); // leaving the dashboard: forget the password
            showHome();
        }).getNode());
    }

    private void openSettings() {
        char[] password = FxDialogs.password(stage, "Open allowlist settings");
        if (password == null) return;
        AdminCredentialStore.Result r = controller.adminAuth().check(password);
        if (!r.success()) {
            FxDialogs.message(stage, "Access denied", "Access denied",
                    controller.verificationProblem(r), FxDialogs.Kind.ERROR);
            return;
        }
        showCard(new FxSettings(controller, this::showHomeCard).getNode());
    }

    // ----------------------------------------------------------------- tray --

    private void setupTray() {
        try {
            if (!SystemTray.isSupported()) return;
            Image icon = FxTheme.image("/icon.png");
            if (icon == null) return;
            java.awt.PopupMenu menu = new java.awt.PopupMenu();
            java.awt.MenuItem show = new java.awt.MenuItem("Show Cheat.Guard");
            show.addActionListener(e -> Platform.runLater(this::restoreFromTray));
            menu.add(show);
            java.awt.Image awt = javax.imageio.ImageIO.read(getClass().getResource("/icon.png"));
            trayIcon = new TrayIcon(awt, "Cheat.Guard", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> Platform.runLater(this::restoreFromTray));
            SystemTray.getSystemTray().add(trayIcon);
            stage.iconifiedProperty().addListener((o, was, is) -> {
                if (is) hideToTray();
            });
        } catch (Exception e) {
            trayIcon = null; // tray unavailable: normal minimizing keeps working
        }
    }

    private void hideToTray() {
        if (trayIcon == null) return;
        Platform.runLater(() -> {
            stage.hide();
            if (!trayHintShown) {
                trayHintShown = true;
                trayIcon.displayMessage("Cheat.Guard", "Still running in the tray — click here to reopen.",
                        TrayIcon.MessageType.INFO);
            }
        });
    }

    private void restoreFromTray() {
        stage.show();
        stage.setIconified(false);
        stage.toFront();
    }

    private void removeTray() {
        try {
            if (trayIcon != null) SystemTray.getSystemTray().remove(trayIcon);
        } catch (Exception ignored) {
        }
    }

    // ------------------------------------------------------- dev screenshots --

    private void takeScreenshots(String dir) {
        System.err.println("FXSHOT: thread starting");
        Thread t = new Thread(() -> {
            try {
                File out = new File(dir);
                out.mkdirs();
                System.err.println("FXSHOT: stage=" + stage);
                Thread.sleep(900);
                shot(out, "home");
                Platform.runLater(() -> showCard(buildSetupCard()));
                Thread.sleep(700);
                shot(out, "setup");
                Platform.runLater(() -> showCard(buildFirstRunCard()));
                Thread.sleep(700);
                shot(out, "first-run");
                Platform.runLater(() -> openSettingsSilent());
                Thread.sleep(1200);
                shot(out, "settings");
                Platform.runLater(() -> showCard(new FxDashboard(controller, new char[0], CheatGuardFxApp.this::showHomeCard).getNode()));
                Thread.sleep(1200);
                shot(out, "dashboard");
                Platform.runLater(this::noop);
                Thread.sleep(400);
                Platform.runLater(() -> showHomeCard());
                Platform.exit();
            } catch (Throwable e) {
                e.printStackTrace();
                System.exit(2);
            }
            System.err.println("FXSHOT: done, exiting");
            System.exit(0);
        }, "CheatGuard-FxShot");
        t.setDaemon(true);
        t.start();
    }

    /** Screenshot path that skips the password prompt (dev builds only). */
    private void openSettingsSilent() {
        showCard(new FxSettings(controller, this::showHomeCard).getNode());
    }

    private void noop() { }

    private void shot(File dir, String name) throws Exception {
        System.err.println("FXSHOT: shot " + name);
        Platform.runLater(stage::toFront);
        Thread.sleep(350);
        int w = (int) stage.getWidth();
        int h = (int) stage.getHeight();
        int x = (int) stage.getX();
        int y = (int) stage.getY();
        java.awt.Robot robot = new java.awt.Robot();
        BufferedImage img = robot.createScreenCapture(new Rectangle(x, y, w, h));
        ImageIO.write(img, "png", new File(dir, name + ".png"));
    }

    // ------------------------------------------------------------- UI kit ----

    private VBox columnCard(double vpad, double hpad) {
        VBox card = new VBox(10);
        card.getStyleClass().add("card");
        card.setPadding(new Insets(vpad, hpad, vpad, hpad));
        card.setMaxWidth(Region.USE_PREF_SIZE);
        return card;
    }

    private StackPane centered(VBox card) {
        StackPane pane = new StackPane(card);
        pane.getStyleClass().add("backdrop");
        StackPane.setAlignment(card, Pos.CENTER);
        return pane;
    }

    private Node brandMark(double width) {
        Image logo = FxTheme.image("/logo.png");
        if (logo == null) {
            Label t = new Label("Cheat.Guard");
            t.getStyleClass().add("h-display");
            return t;
        }
        ImageView view = new ImageView(logo);
        view.setFitWidth(width);
        view.setPreserveRatio(true);
        return view;
    }

    private static Label heading(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("h-title");
        return l;
    }

    private static Label muted(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("text-muted");
        l.setWrapText(true);
        return l;
    }

    private static Region gap(double h) {
        Region r = new Region();
        r.setMinHeight(h);
        return r;
    }

    /** Field with a caption above it. */
    private static VBox captioned(String caption, javafx.scene.control.Control field) {
        Label l = new Label(caption);
        l.getStyleClass().add("text-muted");
        field.setMaxWidth(420);
        VBox box = new VBox(6, l, field);
        box.setAlignment(Pos.CENTER_LEFT);
        return box;
    }

    private static Button pill(String text, String styleClass) {
        Button b = new Button(text);
        b.getStyleClass().add(styleClass);
        return b;
    }

    /** Small record for the monitor's launch/site combos. */
    public record ComboItem(String exe, String display) {
        @Override public String toString() { return display; }
    }

    /** Shared by the monitor footer: invigilator-added apps that are still allowed. */
    static List<ComboItem> launchableApps() {
        LinkedHashSet<String> launchable = new LinkedHashSet<>(AppConfig.getInstance().getAppEntries());
        launchable.retainAll(AppConfig.getInstance().getAllowedProcesses());
        List<ComboItem> out = new ArrayList<>();
        for (String exe : launchable) {
            String real = AppConfig.getInstance().getAppDisplayName(exe);
            out.add(new ComboItem(exe, real != null ? real : ProcessWhitelist.friendlyName(exe)));
        }
        return out;
    }

    /** The monitor screen. Lives while its session does. */
    static final class FxMonitorCard {
        private final CheatGuardFxApp app;
        private final ExamSession session;
        private final BorderPane screen;
        private final ListView<LogRow> logList;
        private final Label status;
        private final Label elapsed;
        private final Label lockPill;
        private final Label alertPill;
        private final Label blockedPill;
        private final Button endBtn;
        private long alerts;
        private long blocked;
        private Timeline clock;

        FxMonitorCard(CheatGuardFxApp app, ExamSession session, boolean starting) {
            this.app = app;
            this.session = session;

            status = starting
                    ? heading("Starting session — approve the administrator prompt")
                    : heading("Session active");
            if (!starting) status.getStyleClass().add("text-accent");
            elapsed = muted("Running 00:00:00");
            elapsed.setVisible(!starting);

            lockPill = chip(starting ? "LOCKING WEBSITES…" : "WEBSITE LOCK ON",
                    starting ? "pill" : "pill pill-teal");
            alertPill = chip("0 ALERTS", "pill");
            blockedPill = chip("0 BLOCKED", "pill");

            HBox left = new HBox(14);
            Image logo = FxTheme.image("/logo.png");
            if (logo != null) {
                ImageView mark = new ImageView(logo);
                mark.setFitWidth(120);
                mark.setPreserveRatio(true);
                left.getChildren().add(mark);
            }
            VBox titles = new VBox(3, status, muted(session.getCourseCode() + "  ·  Student " + session.getStudentId()), elapsed);
            left.getChildren().add(titles);
            left.setAlignment(Pos.CENTER_LEFT);
            HBox pills = new HBox(8, lockPill, alertPill, blockedPill);
            pills.setAlignment(Pos.CENTER_RIGHT);

            BorderPane header = new BorderPane();
            header.getStyleClass().add("card-flat");
            header.setPadding(new Insets(14, 18, 14, 18));
            header.setLeft(left);
            header.setRight(pills);
            BorderPane.setAlignment(pills, Pos.CENTER);

            // Live log: one styled row per audit event, newest at the bottom.
            logList = new ListView<>();
            logList.getStyleClass().add("list-view");
            VBox.setVgrow(logList, Priority.ALWAYS);
            logList.setCellFactory(v -> new javafx.scene.control.ListCell<>() {
                @Override protected void updateItem(LogRow row, boolean empty) {
                    super.updateItem(row, empty);
                    if (empty || row == null) { setGraphic(null); setText(null); return; }
                    getStyleClass().setAll("list-cell", "log-cell");
                    Label time = new Label(row.time);
                    time.getStyleClass().add("log-time");
                    Label tag = new Label(row.tag);
                    tag.getStyleClass().addAll("log-tag", row.tagClass);
                    tag.setMinWidth(56);
                    tag.setAlignment(Pos.CENTER);
                    Label msg = new Label(row.text);
                    msg.getStyleClass().addAll("log-msg", row.msgClass);
                    msg.setWrapText(true);
                    msg.setMaxWidth(640);
                    HBox box = new HBox(10, time, tag, msg);
                    box.setAlignment(Pos.TOP_LEFT);
                    setGraphic(box);
                    setText(null);
                }
            });

            Button openFolder = pill("Open exam folder", "button-ghost");
            openFolder.setOnAction(e -> {
                try { Desktop.getDesktop().open(session.getExamFolder()); }
                catch (Exception ex) { FxDialogs.message(app.stage, "Cheat.Guard", "Could not open the exam folder.", ex.getMessage(), FxDialogs.Kind.ERROR); }
            });

            HBox logHead = new HBox(10, section("Live activity"), spacer(), openFolder);
            logHead.setAlignment(Pos.CENTER_LEFT);
            VBox logCard = new VBox(10, logHead, logList);
            logCard.getStyleClass().add("card");
            logCard.setPadding(new Insets(16, 18, 16, 18));
            VBox.setVgrow(logCard, Priority.ALWAYS);

            // Footer: quick access + the guarded end action.
            ComboBox<ComboItem> appCombo = new ComboBox<>();
            appCombo.getItems().addAll(launchableApps());
            appCombo.setPrefWidth(190);
            Button openApp = pill("Open on exam folder", "button-secondary");
            openApp.setOnAction(e -> {
                ComboItem sel = appCombo.getValue();
                if (sel == null) {
                    FxDialogs.message(app.stage, "Nothing to open", "Nothing to open",
                            "No application has been approved yet. Add one in \"Allowed apps and websites\".",
                            FxDialogs.Kind.INFO);
                    return;
                }
                String problem = AllowedAppLauncher.launch(sel.exe(), session.getExamFolder());
                if (problem != null) FxDialogs.message(app.stage, "Could not open the app", "Could not open the app", problem, FxDialogs.Kind.WARN);
            });
            ComboBox<String> siteCombo = new ComboBox<>();
            siteCombo.getItems().addAll(AppConfig.getInstance().getAllowedSites());
            siteCombo.setPrefWidth(190);
            Button openSite = pill("Open site", "button-secondary");
            openSite.setOnAction(e -> {
                String sel = siteCombo.getValue();
                if (sel == null) return;
                try { Desktop.getDesktop().browse(new URI("https://" + sel)); }
                catch (Exception ex) { FxDialogs.message(app.stage, "Cheat.Guard", "Could not open that site.", ex.getMessage(), FxDialogs.Kind.ERROR); }
            });

            endBtn = pill("End session and seal log", "button-danger");
            endBtn.setDisable(starting);
            endBtn.setOnAction(e -> {
                if (app.controller.sessionBusy()) {
                    FxDialogs.message(app.stage, "Please wait", "Please wait",
                            "A session action is already in progress. Wait a moment.", FxDialogs.Kind.INFO);
                    return;
                }
                char[] password = FxDialogs.password(app.stage, "End exam session");
                if (password == null) return;
                if (password.length == 0) {
                    Arrays.fill(password, '\0');
                    FxDialogs.message(app.stage, "Password required", "Password required",
                            "Enter the administrator password.", FxDialogs.Kind.WARN);
                    return;
                }
                AdminCredentialStore.Result r = app.controller.adminAuth().check(password.clone());
                if (!r.success()) {
                    Arrays.fill(password, '\0');
                    FxDialogs.message(app.stage, "Access denied", "Access denied",
                            app.controller.verificationProblem(r), FxDialogs.Kind.ERROR);
                    return;
                }
                app.controller.requestEndSession(app, session, password);
            });

            VBox quick = new VBox(8,
                    row(caption("Approved apps"), appCombo, openApp),
                    row(caption("Approved sites"), siteCombo, openSite));
            BorderPane footer = new BorderPane();
            footer.getStyleClass().add("card-flat");
            footer.setPadding(new Insets(14, 18, 14, 18));
            footer.setLeft(quick);
            footer.setRight(endBtn);
            BorderPane.setAlignment(endBtn, Pos.CENTER);

            screen = new BorderPane();
            screen.getStyleClass().add("backdrop");
            screen.setPadding(new Insets(20, 22, 20, 22));
            screen.setTop(header);
            screen.setCenter(logCard);
            screen.setBottom(footer);
            BorderPane.setMargin(logCard, new Insets(14, 0, 14, 0));
        }

        Node getNode() { return screen; }

        void setActive() {
            status.setText("Session active");
            status.getStyleClass().add("text-accent");
            lockPill.setText("WEBSITE LOCK ON");
            lockPill.getStyleClass().setAll("pill", "pill-teal");
            elapsed.setVisible(true);
            endBtn.setDisable(false);
            clock = new Timeline(new KeyFrame(javafx.util.Duration.seconds(1), ev -> {
                long sec = java.time.Duration.between(session.getStartTime(), LocalDateTime.now()).getSeconds();
                elapsed.setText(String.format("Running %02d:%02d:%02d", sec / 3600, sec % 3600 / 60, sec % 60));
            }));
            clock.setCycleCount(Timeline.INDEFINITE);
            clock.play();
        }

        void append(Violation v) {
            String text = LogDisplayFormatter.format(v);
            if (text.isBlank()) return;
            boolean red = v.isRedFlag();
            boolean warn = !red && v.getSeverity() == Violation.Severity.NOTICE;
            String time = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            logList.getItems().add(new LogRow(time,
                    red ? "ALERT" : warn ? "BLOCKED" : LogDisplayFormatter.statusOf(v.getSeverity()),
                    red ? "log-tag-alert" : warn ? "log-tag-warn" : "log-tag-ok",
                    red ? "log-msg log-msg-alert" : warn ? "log-msg log-msg-warn" : "log-msg",
                    text));
            // A very long session must not grow the display without bound; the
            // oldest rows are dropped from the DISPLAY only, the sealed log keeps all.
            int over = logList.getItems().size() - 500;
            if (over > 0) logList.getItems().remove(0, over);
            logList.scrollTo(logList.getItems().size() - 1);

            if (red) {
                alerts++;
                alertPill.setText(alerts + (alerts == 1 ? " ALERT" : " ALERTS"));
                alertPill.getStyleClass().setAll("pill", "pill-red");
            }
            if (warn) {
                blocked++;
                blockedPill.setText(blocked + " BLOCKED");
                blockedPill.getStyleClass().setAll("pill", "pill-amber");
            }
        }

        private record LogRow(String time, String tag, String tagClass, String msgClass, String text) {}
    }

    // ------------------------------------------------------------ UI utils --

    private static Label section(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("h-section");
        return l;
    }

    private static Label caption(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("text-dim");
        return l;
    }

    private static HBox row(Node... children) {
        HBox box = new HBox(8, children);
        box.setAlignment(Pos.CENTER_LEFT);
        return box;
    }

    private static Region spacer() {
        Region r = new Region();
        HBox.setHgrow(r, Priority.ALWAYS);
        return r;
    }

    private static Label chip(String text, String styleClass) {
        Label l = new Label(text);
        l.getStyleClass().setAll(styleClass.split(" "));
        return l;
    }

    @Override
    public void stop() {
        removeTray();
    }
}
