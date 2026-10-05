package com.cheatguard.gui;

import com.cheatguard.config.AppConfig;
import com.cheatguard.security.AdminAuth;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.File;
import java.util.List;
import java.util.Set;

/** Administrator screen: allowed applications, allowed websites and the admin password. */
public class SettingsPanel extends JPanel {

    private final AppConfig config = AppConfig.getInstance();
    private final AdminAuth adminAuth;
    private final java.util.function.BooleanSupplier sessionActive;
    private final JComboBox<String> profileCombo = new JComboBox<>();
    private DefaultListModel<String> processModel;
    private DefaultListModel<String> siteModel;

    public SettingsPanel(AdminAuth adminAuth, java.util.function.BooleanSupplier sessionActive, Runnable onBack) {
        this.adminAuth = adminAuth;
        this.sessionActive = sessionActive;
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

        JButton update = UITheme.ghost("Check for update");
        update.addActionListener(e -> checkForUpdate(update));
        JButton back = UITheme.ghost("Back");
        back.addActionListener(e -> onBack.run());
        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        headerButtons.setOpaque(false);
        headerButtons.add(update);
        headerButtons.add(back);
        header.add(headerButtons, BorderLayout.EAST);
        return header;
    }

    /**
     * Ask GitHub whether a newer release exists; offer to download and run the
     * official installer. Never offered while a session is active.
     */
    private void checkForUpdate(JButton button) {
        if (sessionActive.getAsBoolean()) {
            JOptionPane.showMessageDialog(this,
                    "Cheat.Guard cannot update while an exam session is running.",
                    "Session active", JOptionPane.WARNING_MESSAGE);
            return;
        }
        button.setEnabled(false);
        new Thread(() -> {
            java.util.Optional<com.cheatguard.config.UpdateChecker.UpdateInfo> info =
                    com.cheatguard.config.UpdateChecker.checkLatest();
            javax.swing.SwingUtilities.invokeLater(() -> {
                button.setEnabled(true);
                if (info.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                            "Cheat.Guard v" + com.cheatguard.config.UpdateChecker.CURRENT_VERSION
                                    + " is up to date (or the update check could not reach GitHub).",
                            "No update", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                com.cheatguard.config.UpdateChecker.UpdateInfo u = info.get();
                int go = JOptionPane.showConfirmDialog(this,
                        "Cheat.Guard v" + u.version() + " is available.\n"
                                + "Download and run the official installer now?\n\n"
                                + "The app will close while the update installs.",
                        "Update available", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (go != JOptionPane.YES_OPTION) return;
                runUpdate(u);
            });
        }, "CheatGuard-UpdateCheck").start();
    }

    private void runUpdate(com.cheatguard.config.UpdateChecker.UpdateInfo u) {
        setEnabled(false);
        JDialog progress = new JDialog((Frame) null, "Downloading update", false);
        JLabel bar = new JLabel("Downloading Cheat.Guard v" + u.version() + "... 0%");
        bar.setBorder(UITheme.padding(18, 24, 18, 24));
        progress.add(bar);
        progress.setSize(440, 110);
        progress.setLocationRelativeTo(null);
        progress.setVisible(true);
        new Thread(() -> {
            try {
                File target = new File(System.getProperty("java.io.tmpdir"),
                        "CheatGuard-Setup-" + u.version() + ".exe");
                com.cheatguard.config.UpdateChecker.download(u.downloadUrl(), target, pct ->
                        javax.swing.SwingUtilities.invokeLater(() ->
                                bar.setText("Downloading Cheat.Guard v" + u.version() + "... " + pct + "%")));
                javax.swing.SwingUtilities.invokeLater(() -> {
                    progress.dispose();
                    JOptionPane.showMessageDialog(this,
                            "Update downloaded. Cheat.Guard will now close and the installer will run.",
                            "Installing update", JOptionPane.INFORMATION_MESSAGE);
                    try {
                        new ProcessBuilder(target.getAbsolutePath(), "/quiet", "/norestart").start();
                    } catch (Exception ex) {
                        setEnabled(true);
                        return;
                    }
                    System.exit(0);
                });
            } catch (Exception ex) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    progress.dispose();
                    setEnabled(true);
                    JOptionPane.showMessageDialog(this,
                            "The update could not be downloaded: " + ex.getMessage()
                                    + "\nYou can download it manually from the GitHub releases page.",
                            "Update failed", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "CheatGuard-UpdateDownload").start();
    }

    private JComponent buildBody() {
        JPanel columns = new JPanel(new GridLayout(1, 3, 18, 0));
        columns.setOpaque(false);
        columns.add(buildAppCard());
        columns.add(buildSiteCard());
        columns.add(buildSecurityCard());

        JPanel body = new JPanel(new BorderLayout(0, 18));
        body.setOpaque(false);
        body.add(columns, BorderLayout.CENTER);
        body.add(buildProfilesCard(), BorderLayout.SOUTH);
        return body;
    }

    /** Save the current sites + apps under a name; load or delete saved profiles. */
    private JComponent buildProfilesCard() {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel heading = UITheme.section("Exam profiles");
        JLabel hint = UITheme.muted("<html><body style='width:760px'>Save the current websites and apps as a named profile "
                + "and load them before an exam - no re-adding anything. Toolchain entries (compilers, git) are "
                + "machine-wide and are not part of a profile.</body></html>");
        hint.setForeground(UITheme.TEXT_DIM);

        JTextField nameField = new JTextField();
        nameField.setMaximumSize(new Dimension(280, 38));
        nameField.setToolTipText("e.g. CSE exam");
        JButton save = UITheme.secondary("Save profile");
        save.addActionListener(e -> {
            String name = nameField.getText().trim();
            if (name.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Type a profile name first.",
                        "Save profile", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (config.saveProfile(name)) {
                nameField.setText("");
                profileCombo.removeAllItems();
                for (String pName : config.listProfiles()) profileCombo.addItem(pName);
                profileCombo.setSelectedItem(name);
                JOptionPane.showMessageDialog(this, "Profile \"" + name + "\" saved with the current sites and apps.",
                        "Profile saved", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "The profile name may only contain letters, numbers, "
                        + "spaces, dot, dash and underscore.", "Not saved", JOptionPane.WARNING_MESSAGE);
            }
        });
        JPanel saveRow = new JPanel(new BorderLayout(8, 0));
        saveRow.setOpaque(false);
        saveRow.setMaximumSize(new Dimension(760, 44));
        saveRow.add(nameField, BorderLayout.CENTER);
        saveRow.add(save, BorderLayout.EAST);

        profileCombo.setMaximumSize(new Dimension(280, 38));
        for (String pName : config.listProfiles()) profileCombo.addItem(pName);
        JButton load = UITheme.secondary("Load profile");
        load.addActionListener(e -> {
            String selected = (String) profileCombo.getSelectedItem();
            if (selected == null) return;
            config.loadProfile(selected);
            refresh(processModel, config.getAllowedProcesses());
            refresh(siteModel, config.getAllowedSites());
            JOptionPane.showMessageDialog(this,
                    "Profile \"" + selected + "\" loaded. Sites and invigilator apps were replaced; the toolchain stayed.",
                    "Profile loaded", JOptionPane.INFORMATION_MESSAGE);
        });
        JButton delete = UITheme.ghost("Delete profile");
        delete.addActionListener(e -> {
            String selected = (String) profileCombo.getSelectedItem();
            if (selected == null) return;
            config.deleteProfile(selected);
            profileCombo.removeItem(selected);
        });

        JPanel loadRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        loadRow.setOpaque(false);
        loadRow.setMaximumSize(new Dimension(760, 44));
        loadRow.add(profileCombo);
        loadRow.add(load);
        loadRow.add(delete);

        card.add(leftAlign(heading));
        card.add(Box.createVerticalStrut(4));
        card.add(leftAlign(hint));
        card.add(Box.createVerticalStrut(12));
        card.add(leftAlign(saveRow));
        card.add(Box.createVerticalStrut(10));
        card.add(leftAlign(loadRow));
        return card;
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

        // search bar: type keywords ("vs code", "python", "clion") and matching
        // INSTALLED apps appear by their real names; picking one adds the exe it
        // points to. The suggestion list stays HIDDEN until something is typed.
        JTextField search = UITheme.field("Search installed apps...  (e.g. vs code)");
        DefaultListModel<String> matchModel = new DefaultListModel<>();
        JList<String> matches = new JList<>(matchModel);
        UITheme.styleList(matches);
        matches.setVisibleRowCount(6);
        List<com.cheatguard.config.InstalledApps.App> installed =
                com.cheatguard.config.InstalledApps.list();
        List<com.cheatguard.config.InstalledApps.App> shown = new ArrayList<>();
        JScrollPane matchScroll = UITheme.scroll(matches);
        matchScroll.setAlignmentX(LEFT_ALIGNMENT);
        matchScroll.setPreferredSize(new Dimension(300, 120));
        matchScroll.setVisible(false);

        JButton clear = UITheme.ghost("Clear");
        clear.addActionListener(e -> {
            search.setText("");
            search.requestFocusInWindow();
        });
        Runnable refill = () -> {
            String q = search.getText().trim().toLowerCase();
            shown.clear();
            matchModel.clear();
            if (!q.isEmpty()) {
                for (com.cheatguard.config.InstalledApps.App app : installed) {
                    if (matchesKeywords(app, q)) {
                        shown.add(app);
                        matchModel.addElement(app.displayName());
                    }
                }
            }
            boolean show = !q.isEmpty();
            matchScroll.setVisible(show);
            search.getParent().revalidate();
        };
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { refill.run(); }
        });

        JButton add = UITheme.secondary("Add selected");
        add.addActionListener(e -> {
            int idx = matches.getSelectedIndex();
            if (idx < 0 || idx >= shown.size()) return;
            com.cheatguard.config.InstalledApps.App app = shown.get(idx);
            String[] shortcut = com.cheatguard.config.InstalledApps.resolveShortcut(app.lnkPath());
            String target = shortcut[0];
            if (target == null || target.isBlank()
                    || !target.toLowerCase().endsWith(".exe")) {
                JOptionPane.showMessageDialog(this,
                        "Could not resolve that app's program file.", "Not added",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            java.io.File exe = new java.io.File(target);
            config.addAllowedProcessPath(exe);
            config.setAppDisplayName(exe.getName(), app.displayName());
            config.addAppEntry(exe.getName());
            // Keep the shortcut's launch arguments (Squirrel-style launchers such as
            // Discord's Update.exe need "--processStart <app>.exe" to open at all).
            config.setProcessArgs(exe.getName(), shortcut[1]);
            refresh(processModel, config.getAllowedProcesses());
            search.setText("");
            search.requestFocusInWindow();
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
                config.addAppEntry(exe.getName());
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
                list, search, matchScroll, add, browse, clear, remove);
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

    /**
     * Keyword search: EVERY word must match. A word matches when it appears in
     * the app's name or shortcut name, or when it is an abbreviation made of the
     * name's word initials - so "vs code" finds Visual Studio Code.
     */
    private boolean matchesKeywords(com.cheatguard.config.InstalledApps.App app, String query) {
        for (String word : query.split("\\s+")) {
            if (word.isEmpty()) continue;
            if (!wordMatches(app, word)) return false;
        }
        return true;
    }

    private boolean wordMatches(com.cheatguard.config.InstalledApps.App app, String word) {
        String base = new java.io.File(app.lnkPath()).getName();
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

    /** The applications card: heading, hint, allowed list, search picker, actions. */
    private JComponent appCard(String heading, String hintText, JList<String> list,
                               JTextField search, JScrollPane matchScroll, JButton add,
                               JButton extra, JButton clear, JButton remove) {
        JPanel card = UITheme.card();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JScrollPane scroll = UITheme.scroll(list);
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        scroll.setPreferredSize(new Dimension(300, 220));

        search.setMaximumSize(new Dimension(460, 40));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setOpaque(false);
        actions.setAlignmentX(LEFT_ALIGNMENT);
        actions.add(add);
        if (extra != null) actions.add(extra);
        actions.add(clear);
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
