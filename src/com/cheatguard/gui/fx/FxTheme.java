package com.cheatguard.gui.fx;

import javafx.scene.image.Image;
import javafx.scene.text.Font;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the bundled typography and artwork for the JavaFX interface.
 *
 * <p>The interface uses Inter (SIL Open Font License) shipped inside the jar so
 * every machine - including old exam laptops with broken font substitutions -
 * renders the exact same professional type. The weights load under their own
 * family names ("Inter", "Inter Medium", "Inter SemiBold", "Inter Bold") so CSS
 * can pick them directly.
 */
public final class FxTheme {

    private static boolean loaded;
    private static final List<Image> APP_ICONS = new ArrayList<>();

    public static synchronized void load() {
        if (loaded) return;
        loaded = true;
        for (String weight : new String[]{
                "Inter-Regular", "Inter-Medium", "Inter-SemiBold", "Inter-Bold"}) {
            InputStream in = FxTheme.class.getResourceAsStream("/fonts/" + weight + ".ttf");
            if (in != null) Font.loadFont(in, 13);
        }
        for (String size : new String[]{"16", "32", "48", "256"}) {
            InputStream in = FxTheme.class.getResourceAsStream("/icon-" + size + ".png");
            if (in != null) APP_ICONS.add(new Image(in));
        }
        if (APP_ICONS.isEmpty()) {
            InputStream in = FxTheme.class.getResourceAsStream("/icon.png");
            if (in != null) APP_ICONS.add(new Image(in));
        }
    }

    /** Window/taskbar icons at several resolutions for crisp scaling. */
    public static List<Image> appIcons() {
        load();
        return APP_ICONS;
    }

    /** A resource image, or null when missing (callers fall back to text). */
    public static Image image(String resource) {
        load();
        InputStream in = FxTheme.class.getResourceAsStream(resource);
        return in == null ? null : new Image(in);
    }

    private FxTheme() {
    }
}
