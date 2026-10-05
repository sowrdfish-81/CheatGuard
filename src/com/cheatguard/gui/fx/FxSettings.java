package com.cheatguard.gui.fx;

import com.cheatguard.Main;
import com.cheatguard.config.AppConfig;
import com.cheatguard.config.InstalledApps;
import com.cheatguard.watchdog.ProcessWhitelist;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Administrator screen: allowed applications (with the installed-app search
 * picker), allowed websites and the administrator password - the JavaFX port of
 * the Swing settings panel, same flows and rules, modern rendering.
 */
final class FxSettings {

    private final AppConfig config = AppConfig.getInstance();
    private final Main controller;
    private final Runnable onBack;
    private final ListView<String> processList = new ListView<>();
    private final ListView<String> siteList = new ListView<>();
    private final ListView<String> matchList = new ListView<>();
    private final TextField search = new TextField();
    private final VBox matchBox = new VBox(6);
    private final List<InstalledApps.App> shown = new ArrayList<>();
    private final List<InstalledApps.App> installed = InstalledApps.list();
    private final Label appStatus = new Label(" ");
    private final Label siteStatus = new Label(" ");

    private final Node node;

    FxSettings(Main controller, Runnable onBack) {
        this.controller = controller;
        this.onBack = onBack;

        // ------------------------------------------------------- apps card --
        refresh(processList, config.getAllowedProcesses());
        processList.setCellFactory(v -> new ListCell<>() {
            @Override protected void updateItem(String exe, boolean empty) {
                super.updateItem(exe, empty);
                setText(empty || exe == null ? null : displayName(exe));
            }
        });
        processList.setPrefHeight(230);

        search.setPromptText("Search installed apps...  (e.g. vs code)");
        matchList.setPrefHeight(150);
        matchList.setCellFactory(v -> new ListCell<>() {
            @Override protected void updateItem(String name, boolean empty) {
                super.updateItem(name, empty);
                setText(empty || name == null ? null : name);
            }
        });
        matchBox.getChildren().add(matchList);
        matchBox.setVisible(false);
        matchBox.setManaged(false);

        search.textProperty().addListener((o, was, now) -> refillMatches(now));

        Button add = compactButton("Add", "button-secondary");
        Button browse = compactButton("Choose .exe", "button-secondary");
        Button clear = compactButton("Clear", "button-ghost");
        Button remove = compactButton("Remove", "button-ghost");

        add.setOnAction(e -> addSelected(add));
        browse.setOnAction(e -> chooseExe(browse));
        clear.setOnAction(e -> {
            search.setText("");
            search.requestFocus();
        });
        remove.setOnAction(e -> {
            String selected = processList.getSelectionModel().getSelectedItem();
            if (selected == null) return;
            config.removeAllowedProcess(selected);
            refresh(processList, config.getAllowedProcesses());
        });

        javafx.scene.layout.FlowPane appActions = new javafx.scene.layout.FlowPane(8, 8, add, browse, clear, remove);
        appActions.setPrefWrapLength(300);

        VBox appsCard = card("Allowed applications",
                "Add apps by searching their real names - anything else a student opens is closed automatically. "
                        + "Use \"Choose .exe\" for a portable program.",
                new Node[]{processList, search, matchBox, appActions, appStatus});

        // ------------------------------------------------------- sites card --
        refresh(siteList, config.getAllowedSites());
        TextField siteInput = new TextField();
        siteInput.setPromptText("codeforces.com");
        Button siteAdd = compactButton("Add", "button-secondary");
        Button siteRemove = compactButton("Remove", "button-ghost");
        siteList.setPrefHeight(300);

        Runnable siteAddAction = () -> {
            String value = siteInput.getText().trim();
            if (value.isEmpty()) return;
            int before = config.getAllowedSites().size();
            config.addAllowedSite(value);
            refresh(siteList, config.getAllowedSites());
            if (config.getAllowedSites().size() == before) {
                siteStatus.getStyleClass().setAll("text-danger");
                siteStatus.setText("\"" + value + "\" is not a valid domain. Use a full name such as codeforces.com.");
            } else {
                siteStatus.getStyleClass().setAll("text-muted");
                siteStatus.setText(" ");
            }
            siteInput.setText("");
        };
        siteAdd.setOnAction(e -> siteAddAction.run());
        siteInput.setOnAction(e -> siteAddAction.run());
        siteRemove.setOnAction(e -> {
            String selected = siteList.getSelectionModel().getSelectedItem();
            if (selected == null) return;
            config.removeAllowedSite(selected);
            refresh(siteList, config.getAllowedSites());
        });

        HBox siteAddRow = new HBox(8, siteInput, siteAdd);
        HBox.setHgrow(siteInput, Priority.ALWAYS);
        siteAddRow.setAlignment(Pos.CENTER_LEFT);
        VBox sitesCard = card("Allowed websites",
                "Subdomains are included automatically. Every other domain fails to resolve during a session.",
                new Node[]{siteList, siteAddRow, siteRemove, siteStatus});

        // --------------------------------------------------- security card --
        PasswordField current = new PasswordField();
        current.setPromptText("Current password");
        PasswordField next = new PasswordField();
        next.setPromptText("New password");
        PasswordField repeat = new PasswordField();
        repeat.setPromptText("Repeat new password");
        Label status = new Label(" ");
        status.setWrapText(true);
        Button apply = compactButton("Update password", "button-secondary");

        apply.setOnAction(e -> {
            char[] a = current.getText().toCharArray();
            char[] b = next.getText().toCharArray();
            char[] c = repeat.getText().toCharArray();
            try {
                if (!Arrays.equals(b, c)) {
                    status.getStyleClass().setAll("text-danger");
                    status.setText("The new passwords do not match.");
                    return;
                }
                controller.adminAuth().changePassword(a, b);
                status.getStyleClass().setAll("text-accent");
                status.setText("Password updated.");
            } catch (IllegalArgumentException | SecurityException refused) {
                status.getStyleClass().setAll("text-danger");
                status.setText(refused.getMessage());
            } catch (Exception ex) {
                status.getStyleClass().setAll("text-danger");
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

        VBox securityCard = card("Administrator password",
                "Stored only as a salted PBKDF2 digest, tied to this computer. It cannot be read back from the "
                        + "app, the installer or the source code.",
                new Node[]{caption("Current password"), current, caption("New password"), next,
                        caption("Repeat new password"), repeat, apply, status});

        // ---------------------------------------------------------------- body --
        HBox columns = new HBox(16, appsCard, sitesCard, securityCard);
        for (Node card : new Node[]{appsCard, sitesCard, securityCard}) {
            HBox.setHgrow(card, Priority.ALWAYS);
            ((VBox) card).setPrefWidth(340);
        }

        Label title = new Label("Exam allowlist");
        title.getStyleClass().add("h-title");
        Label subtitle = new Label("Only the applications and websites listed here stay usable during a session.");
        subtitle.getStyleClass().add("text-muted");
        Button back = compactButton("Back", "button-ghost");
        back.setOnAction(e -> onBack.run());

        BorderPane header = new BorderPane();
        header.setLeft(new VBox(4, title, subtitle));
        header.setRight(back);
        header.setPadding(new Insets(0, 0, 16, 0));
        BorderPane.setAlignment(back, Pos.CENTER);

        ScrollPane body = new ScrollPane(columns);
        body.setFitToWidth(true);
        body.setFitToHeight(true);
        body.getStyleClass().add("scroll-pane");

        BorderPane root = new BorderPane();
        root.getStyleClass().add("backdrop");
        root.setPadding(new Insets(22, 24, 22, 24));
        root.setTop(header);
        root.setCenter(body);
        node = root;
    }

    Node getNode() { return node; }

    // ------------------------------------------------------------- actions --

    private void refillMatches(String query) {
        String q = query.trim().toLowerCase();
        shown.clear();
        matchList.getItems().clear();
        if (!q.isEmpty()) {
            for (InstalledApps.App app : installed) {
                if (matchesKeywords(app, q)) {
                    shown.add(app);
                    matchList.getItems().add(app.displayName());
                }
            }
        }
        boolean show = !q.isEmpty();
        matchBox.setVisible(show);
        matchBox.setManaged(show);
        appStatus.getStyleClass().setAll("text-muted");
        appStatus.setText(" ");
    }

    private void addSelected(Button add) {
        int idx = matchList.getSelectionModel().getSelectedIndex();
        if (idx < 0 || idx >= shown.size()) return;
        InstalledApps.App app = shown.get(idx);
        add.setDisable(true);
        appStatus.getStyleClass().setAll("text-muted");
        appStatus.setText("Resolving " + app.displayName() + "…");
        new Thread(() -> {
            String[] shortcut = InstalledApps.resolveShortcut(app.lnkPath());
            Platform.runLater(() -> {
                add.setDisable(false);
                String target = shortcut[0];
                if (target == null || target.isBlank() || !target.toLowerCase().endsWith(".exe")) {
                    appStatus.getStyleClass().setAll("text-danger");
                    appStatus.setText("Could not resolve that app's program file.");
                    return;
                }
                File exe = new File(target);
                config.addAllowedProcessPath(exe);
                config.setAppDisplayName(exe.getName(), app.displayName());
                config.addAppEntry(exe.getName());
                // Keep the shortcut's launch arguments (Squirrel-style launchers such
                // as Discord's Update.exe need "--processStart <app>.exe" to open).
                config.setProcessArgs(exe.getName(), shortcut[1]);
                refresh(processList, config.getAllowedProcesses());
                appStatus.getStyleClass().setAll("text-accent");
                appStatus.setText(app.displayName() + " added.");
                search.setText("");
                search.requestFocus();
            });
        }, "CheatGuard-ResolveApp").start();
    }

    private void chooseExe(Button browse) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose an application to allow");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Windows applications (*.exe)", "*.exe"));
        File exe = chooser.showOpenDialog(CheatGuardFxApp.primaryStage());
        if (exe == null) return;
        browse.setDisable(true);
        new Thread(() -> {
            String real = realAppName(exe);
            Platform.runLater(() -> {
                browse.setDisable(false);
                config.addAllowedProcessPath(exe);
                config.setAppDisplayName(exe.getName(), real);
                config.addAppEntry(exe.getName());
                refresh(processList, config.getAllowedProcesses());
                appStatus.getStyleClass().setAll("text-accent");
                appStatus.setText((real != null ? real : exe.getName()) + " added.");
            });
        }, "CheatGuard-ChooseExe").start();
    }

    /** Read an exe's real name from its version information (best effort). */
    private String realAppName(File exe) {
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
        return real != null ? real : ProcessWhitelist.friendlyName(exeName);
    }

    /**
     * Keyword search: EVERY word must match. A word matches when it appears in
     * the app's name or shortcut name, or when it is an abbreviation made of the
     * name's word initials - so "vs code" finds Visual Studio Code.
     */
    private boolean matchesKeywords(InstalledApps.App app, String query) {
        for (String word : query.split("\\s+")) {
            if (word.isEmpty()) continue;
            if (!wordMatches(app, word)) return false;
        }
        return true;
    }

    private boolean wordMatches(InstalledApps.App app, String word) {
        String base = new File(app.lnkPath()).getName();
        if (base.toLowerCase().endsWith(".lnk")) {
            base = base.substring(0, base.length() - 4);
        }
        String hay = (app.displayName() + " " + base).toLowerCase();
        if (hay.contains(word)) return true;
        // initialism: "vs" -> the first letters of the name's words, in order
        StringBuilder initials = new StringBuilder();
        for (String w : hay.split(" ")) {
            if (!w.isEmpty()) initials.append(w.charAt(0));
        }
        int at = 0;
        for (char c : word.toCharArray()) {
            at = initials.indexOf(String.valueOf(c), at);
            if (at < 0) return false;
            at++;
        }
        return true;
    }

    private void refresh(ListView<String> list, java.util.Set<String> values) {
        list.getItems().setAll(values);
    }

    // ------------------------------------------------------------- UI kit ----

    private VBox card(String heading, String hint, Node[] content) {
        Label h = new Label(heading);
        h.getStyleClass().add("h-section");
        Label hintLabel = new Label(hint);
        hintLabel.getStyleClass().add("text-dim");
        hintLabel.setWrapText(true);

        VBox inner = new VBox(10);
        inner.setSpacing(10);
        inner.getChildren().add(h);
        inner.getChildren().add(hintLabel);
        for (Node n : content) {
            inner.getChildren().add(n);
            if (n instanceof ListView) VBox.setVgrow(n, Priority.ALWAYS);
        }

        VBox card = new VBox(10);
        card.getStyleClass().add("card");
        card.setPadding(new Insets(16, 18, 16, 18));
        card.getChildren().add(inner);
        VBox.setVgrow(inner, Priority.ALWAYS);
        return card;
    }

    private Label caption(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("text-muted");
        return l;
    }

    private static Button compactButton(String text, String styleClass) {
        Button b = new Button(text);
        b.getStyleClass().addAll(styleClass, "button-compact");
        return b;
    }
}
