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
