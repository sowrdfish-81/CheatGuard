package com.cheatguard.gui;

import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.*;

/**
 * The one ButtonUI for the whole app: every JButton (dialog OK/Cancel, file
 * chooser, anything the LAF creates) paints as a dark rounded pill that matches
 * the hand-painted buttons, with hover and press feedback from the button model.
 * Buttons marked with the "cheatguard.customPaint" client property already draw
 * themselves and are left alone.
 */
public class RoundedButtonUI extends BasicButtonUI {

    private static final Color BASE = new Color(0x1E232C);
    private static final Color HOVER = new Color(0x262C38);
    private static final Color PRESS = new Color(0x171B22);
    private static final Color OUTLINE = new Color(0x2A313D);

    @Override
    public void installDefaults(AbstractButton b) {
        super.installDefaults(b);
        b.setOpaque(false);
        b.setForeground(UITheme.TEXT_WHITE);
        b.setBackground(BASE);
        b.setBorder(BorderFactory.createEmptyBorder(9, 18, 9, 18));
        b.setRolloverEnabled(true);
        b.setFocusPainted(false);
    }

    @Override
    public void paint(Graphics g, JComponent c) {
        AbstractButton b = (AbstractButton) c;
        if (b.getClientProperty("cheatguard.customPaint") == null) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            Color fill = !b.isEnabled() ? UITheme.BG_ELEVATED
                    : b.getModel().isPressed() ? PRESS
                    : b.getModel().isRollover() ? HOVER
                    : BASE;
            g2.setColor(fill);
            // fully rounded sides: the corners follow the button's own height
            int r = Math.min(c.getHeight() / 2, 20);
            g2.fillRoundRect(0, 0, c.getWidth(), c.getHeight(), r, r);
            g2.setColor(UITheme.BORDER);
            g2.drawRoundRect(0, 0, c.getWidth() - 1, c.getHeight() - 1, r, r);
            g2.dispose();
        }
        super.paint(g, c);
    }

    @Override
    protected void paintFocus(Graphics g, AbstractButton b, Rectangle viewRect,
                              Rectangle textRect, Rectangle iconRect) {
        // invisible: the dark theme already shows hover/press states
    }
}
