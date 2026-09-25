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
