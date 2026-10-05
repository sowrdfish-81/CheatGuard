package com.cheatguard.gui.fx;

import com.cheatguard.Main;
import com.cheatguard.config.AppPaths;
import com.cheatguard.gui.LogDisplayFormatter;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.SecurityVault;
import javafx.application.Platform;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.SplitPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.io.File;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Admin log dashboard: open, inspect and delete sealed or interrupted sessions.
 * JavaFX port of the Swing dashboard - same vault flow, modern rendering.
 */
final class FxDashboard {

    private final Main controller;
    private final SecurityVault vault;
    /** The password verified at the dashboard door - reused for open and delete. */
    private final char[] sessionPassword;
    private final Runnable onBack;

    private final ListView<File> logList = new ListView<>();
    private final ListView<LineRow> outputList = new ListView<>();
    private final Label summaryLabel = new Label("Select a session log.");
    private final Label studentValue = statValue("—");
    private final Label courseValue = statValue("—");
    private final Label startValue = statValue("—");
    private final Label endValue = statValue("—");
    private final Label durationValue = statValue("—");
    private final Label redValue = statValue("0");
    private final Button openBtn;

    private record LineRow(String text, String cls) {}

    FxDashboard(Main controller, char[] sessionPassword, Runnable onBack) {
        this.controller = controller;
        this.vault = new SecurityVault(controller.adminAuth());
        this.sessionPassword = sessionPassword == null ? new char[0] : sessionPassword;
        this.onBack = onBack;

        openBtn = chipButton("Open session", "button-primary");
        openBtn.setOnAction(e -> openSelected());

        Button refresh = chipButton("Refresh", "button-ghost");
        refresh.setOnAction(e -> refreshLogs());
        Button delete = chipButton("Delete selected", "button-ghost");
        delete.setOnAction(e -> deleteSelected());

        // ---- left: saved sessions ----
        logList.setCellFactory(v -> new ListCell<>() {
            @Override protected void updateItem(File f, boolean empty) {
                super.updateItem(f, empty);
                if (empty || f == null) { setGraphic(null); setText(null); return; }
                boolean unsealed = f.getName().toLowerCase().endsWith(".dat");
                Label name = new Label((unsealed ? "[UNSEALED] " : "") + f.getName());
                name.setWrapText(true);
                name.getStyleClass().add(unsealed ? "text-warn" : "log-msg");
                setGraphic(name);
                setText(null);
            }
        });
        VBox leftCard = card(new VBox(10, section("Saved sessions"), grow(logList),
                new HBox(8, refresh, delete)));
        leftCard.setPrefWidth(330);

        // ---- right: details ----
        HBox openRow = new HBox(10,
                mutedSmall("Verified at the door — open or delete sessions freely."), spacer(), openBtn);
        openRow.setAlignment(Pos.CENTER_LEFT);

        GridPane stats = new GridPane();
        stats.setHgap(10);
        stats.setVgap(10);
        for (int i = 0; i < 3; i++) {
            ColumnConstraints c = new ColumnConstraints();
            c.setPercentWidth(33.33);
            stats.getColumnConstraints().add(c);
        }
        stats.add(statCard("Student ID", studentValue), 0, 0);
        stats.add(statCard("Course", courseValue), 1, 0);
        stats.add(statCard("RED flags", redValue), 2, 0);
        stats.add(statCard("Start", startValue), 0, 1);
        stats.add(statCard("End", endValue), 1, 1);
        stats.add(statCard("Duration", durationValue), 2, 1);

        outputList.setCellFactory(v -> new ListCell<>() {
            @Override protected void updateItem(LineRow row, boolean empty) {
                super.updateItem(row, empty);
                if (empty || row == null) { setGraphic(null); setText(null); return; }
                Label l = new Label(row.text);
                l.setWrapText(true);
                l.getStyleClass().addAll("log-msg", row.cls);
                l.maxWidthProperty().bind(widthProperty().subtract(28));
                setGraphic(l);
                setText(null);
            }
        });

        VBox rightCard = card(new VBox(10, openRow, stats, section("Session log"), grow(outputList)));

        SplitPane split = new SplitPane(leftCard, rightCard);
        split.setOrientation(Orientation.HORIZONTAL);
        split.setDividerPositions(0.32);

        Label title = new Label("Session dashboard");
        title.getStyleClass().add("h-title");
        Button back = chipButton("Back", "button-ghost");
        back.setOnAction(e -> {
            Arrays.fill(sessionPassword, '\0'); // leaving the dashboard: forget the password
            onBack.run();
        });
        summaryLabel.getStyleClass().add("text-muted");
        summaryLabel.setWrapText(true);

        BorderPane header = new BorderPane();
        header.setLeft(new VBox(4, title, summaryLabel));
        header.setRight(back);
        BorderPane.setAlignment(back, Pos.CENTER);

        BorderPane root = new BorderPane();
        root.getStyleClass().add("backdrop");
        root.setPadding(new Insets(22, 24, 22, 24));
        root.setTop(header);
        root.setCenter(split);
        node = root;

        refreshLogs();
    }

    private final Node node;
    Node getNode() { return node; }

    private void refreshLogs() {
        File[] files = AppPaths.getVaultDirectory().listFiles((dir, name) -> {
            String n = name.toLowerCase();
            return n.endsWith(".vault") || n.endsWith(".dat");
        });
        logList.getItems().clear();
        if (files != null) {
            Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
            logList.getItems().addAll(files);
        }
        summaryLabel.setText(logList.getItems().size()
                + " saved session(s). [UNSEALED] means the app was force-stopped before the exam ended normally.");
    }

    private void openSelected() {
        File selected = logList.getSelectionModel().getSelectedItem();
        if (selected == null) {
            CheatGuardFxApp.dialog("Select a session first.");
            return;
        }
        if (sessionPassword.length == 0) {
            CheatGuardFxApp.dialog("Open the dashboard with the admin password first.");
            return;
        }
        // Opening derives a PBKDF2 key and can read a large log; do it off the FX thread.
        new Thread(() -> {
            String content;
            try {
                content = vault.openLog(selected, sessionPassword.clone());
            } catch (Exception ex) {
                Platform.runLater(() -> CheatGuardFxApp.dialog("Could not open log: " + ex.getMessage()));
                return;
            }
            boolean unsealed = selected.getName().toLowerCase().endsWith(".dat");
            Platform.runLater(() -> renderLogWithHighlights(content, unsealed));
        }, "CheatGuard-LogOpen").start();
    }

    private void deleteSelected() {
        File selected = logList.getSelectionModel().getSelectedItem();
        if (selected == null) {
            CheatGuardFxApp.dialog("Select a session first.");
            return;
        }
        if (sessionPassword.length == 0) {
            CheatGuardFxApp.dialog("Open the dashboard with the admin password first.");
            return;
        }
        boolean ok = FxDialogs.confirm(CheatGuardFxApp.primaryStage(), "Delete log", "Permanently delete this student log?",
                selected.getName(), FxDialogs.Kind.WARN);
        if (!ok) return;
        // Deleting a protected log can raise a Windows elevation prompt that waits on
        // the invigilator; keep the window responsive while it runs.
        new Thread(() -> {
            try {
                vault.deleteLog(selected, sessionPassword.clone());
                Platform.runLater(() -> {
                    outputList.getItems().clear();
                    resetStats();
                    refreshLogs();
                });
            } catch (Exception ex) {
                Platform.runLater(() -> CheatGuardFxApp.dialog("Could not delete log: " + ex.getMessage()));
            }
        }, "CheatGuard-LogDelete").start();
    }

    private void renderLogWithHighlights(String content, boolean unsealed) {
        outputList.getItems().clear();
        int redFlags = 0;
        int blockedAttempts = 0;
        String student = "—", course = "—", start = "—";
        String end = unsealed ? "FORCE-STOPPED" : "—";
        String duration = unsealed ? "Unknown" : "—";
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
            if (!display.isEmpty()) {
                outputList.getItems().add(new LineRow(display,
                        red ? "log-msg-alert" : warn ? "log-msg-warn" : "log-msg"));
            }
        }
        studentValue.setText(student);
        courseValue.setText(course);
        startValue.setText(start);
        endValue.setText(end);
        durationValue.setText(duration);
        redValue.setText(Integer.toString(redFlags));
        redValue.getStyleClass().removeAll("text-danger", "text-accent");
        redValue.getStyleClass().add(redFlags > 0 ? "text-danger" : "text-accent");
        summaryLabel.setText((unsealed ? "UNSEALED / interrupted session" : "Sealed session")
                + " — " + redFlags + " RED-FLAG event(s)"
                + (blockedAttempts > 0 ? ", " + blockedAttempts + " blocked website attempt(s)" : ""));
    }

    private String timestamp(String line) { return line.length() >= 19 ? line.substring(0, 19) : "—"; }

    private String field(String line, String key) {
        int at = line.indexOf(key);
        if (at < 0) return "—";
        at += key.length();
        int end = line.indexOf(" | ", at);
        if (end < 0) end = line.length();
        return line.substring(at, end).trim();
    }

    private String formatDuration(long sec) {
        long h = sec / 3600; long m = (sec % 3600) / 60; long s = sec % 60;
        return String.format("%02d:%02d:%02d", h, m, s);
    }

    private void resetStats() {
        studentValue.setText("—"); courseValue.setText("—"); startValue.setText("—");
        endValue.setText("—"); durationValue.setText("—"); redValue.setText("0");
    }

    // ------------------------------------------------------------- UI kit ----

    private static VBox card(VBox content) {
        VBox card = new VBox(10);
        card.getStyleClass().add("card");
        card.setPadding(new Insets(16, 18, 16, 18));
        content.getChildren().forEach(child -> VBox.setVgrow(child, Priority.ALWAYS));
        VBox inner = new VBox(10);
        inner.getChildren().setAll(content.getChildren());
        card.getChildren().add(inner);
        VBox.setVgrow(inner, Priority.ALWAYS);
        return card;
    }

    private static <T extends Node> T grow(T node) {
        VBox.setVgrow(node, Priority.ALWAYS);
        return node;
    }

    private static Node statCard(String label, Label value) {
        Label l = new Label(label.toUpperCase());
        l.getStyleClass().add("text-dim");
        VBox p = new VBox(4, l, value);
        p.getStyleClass().add("stat-card");
        return p;
    }

    private static Label statValue(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("h-section");
        return l;
    }

    private static Label section(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("h-section");
        return l;
    }

    private static Label mutedSmall(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("text-muted");
        l.setWrapText(true);
        return l;
    }

    private static Region spacer() {
        Region r = new Region();
        HBox.setHgrow(r, Priority.ALWAYS);
        return r;
    }

    private static Button chipButton(String text, String styleClass) {
        Button b = new Button(text);
        b.getStyleClass().add(styleClass);
        return b;
    }
}
