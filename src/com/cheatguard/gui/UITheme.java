package com.cheatguard.gui;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
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
                g2.drawOval(cx - 9, cy - 5, 18, 10);
                g2.fillOval(cx - 3, cy - 3, 6, 6);
                // Slash while the text is visible: the icon always shows what a click does.
                if (isSelected()) g2.drawLine(cx + 8, cy - 7, cx - 8, cy + 7);
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
