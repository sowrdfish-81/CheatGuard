package com.cheatguard.watchdog;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;

/**
 * Prepares the Windows desktop environment at the start of an exam session.
 *
 * <p>Anything a student copied <em>before</em> the exam — notes, code, an answer from
 * a chat app — would otherwise still be one paste away, so the clipboard is emptied
 * when a session starts.
 *
 * <p>Emptying the clipboard is not enough on its own: Windows keeps a clipboard
 * <em>history</em> (Win+V) and clearing the current item leaves that history intact,
 * so a student could simply press Win+V and pick a pre-exam entry. The history is
 * therefore discarded as well — Windows drops the stored entries when the feature is
 * switched off, so it is toggled off and immediately restored to the value the user
 * had.
 *
 * <p>The clipboard stays fully usable during the session. Copy and paste, and Win+V
 * for anything copied after the session started, all work as normal; only the
 * pre-session contents are gone.
 */
public final class SessionEnvironment {

    private static final String CLIPBOARD_KEY = "HKCU\\Software\\Microsoft\\Clipboard";

    private Integer previousHistory;
    private boolean toggledHistory;

    /** Empty the clipboard and discard pre-session clipboard history. */
    public void prepare() {
        clearClipboard();
        if (!isWindows()) return;
        clearClipboardHistory();
        clearRecentItems();
    }

    /**
     * Wipe the Windows "Recent items" lists: Start-menu recent files, jump lists
     * and the recent list inside common Open/Save dialogs. They are only
     * auto-generated shortcuts, and they are exactly how a pre-exam file would be
     * reopened inside an ALLOWED app one click after the session starts. The
     * files themselves are untouched.
     */
    private void clearRecentItems() {
        run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "Remove-Item -LiteralPath \"$env:APPDATA\\Microsoft\\Windows\\Recent\\*\" "
                        + "-Recurse -Force -ErrorAction SilentlyContinue");
    }

    /**
     * Safety net for an interrupted {@link #prepare()}. The history setting is put
     * back inside prepare itself, so normally there is nothing left to do here — the
     * clipboard is deliberately left alone so a student does not lose work.
     */
    public void restore() {
        if (toggledHistory && isWindows()) {
            restoreDword("EnableClipboardHistory", previousHistory);
            toggledHistory = false;
        }
    }

    /**
     * Discard stored clipboard history. The documented WinRT call is tried first; if
     * it is unavailable, switching the feature off drops the stored entries, and the
     * user's original setting is restored immediately afterwards so Win+V keeps
     * working during the exam.
     */
    private void clearClipboardHistory() {
        if (run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "[Windows.ApplicationModel.DataTransfer.Clipboard,Windows.ApplicationModel.DataTransfer,"
                        + "ContentType=WindowsRuntime] | Out-Null; "
                        + "[Windows.ApplicationModel.DataTransfer.Clipboard]::ClearHistory() | Out-Null")) {
            return;
        }
        previousHistory = readDword("EnableClipboardHistory");
        toggledHistory = true;
        writeDword("EnableClipboardHistory", 0);
        sleep(400);
        restoreDword("EnableClipboardHistory", previousHistory);
        toggledHistory = false;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /** Empty both the Java-visible clipboard and the Windows clipboard buffer. */
    public void clearClipboard() {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(""), null);
        } catch (Exception ignored) {
            // headless or clipboard owned by another process
        }
        if (!isWindows()) return;
        // Set-Clipboard with no value empties the native clipboard, including formats
        // (images, files) that the Java clipboard API would not replace.
        run("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
                "Set-Clipboard -Value $null -ErrorAction SilentlyContinue; "
                        + "Add-Type -AssemblyName System.Windows.Forms; "
                        + "[System.Windows.Forms.Clipboard]::Clear()");
    }

    // ------------------------------------------------------------- primitives

    private Integer readDword(String name) {
        String out = capture("reg", "query", CLIPBOARD_KEY, "/v", name);
        int at = out.indexOf("REG_DWORD");
        if (at < 0) return null;
        String tail = out.substring(at + 9).trim();
        int end = tail.indexOf('\n');
        if (end > 0) tail = tail.substring(0, end).trim();
        try {
            return Integer.decode(tail);
        } catch (Exception e) {
            return null;
        }
    }

    private void writeDword(String name, int value) {
        run("reg", "add", CLIPBOARD_KEY, "/v", name, "/t", "REG_DWORD",
                "/d", Integer.toString(value), "/f");
    }

    private void restoreDword(String name, Integer previous) {
        if (previous == null) {
            run("reg", "delete", CLIPBOARD_KEY, "/v", name, "/f");
        } else {
            writeDword(name, previous);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    /** Run a command; true when it reported success. */
    private static boolean run(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception ignored) {
            // best effort; a clipboard tweak must never stop an exam
            return false;
        }
    }

    private static String capture(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            return out;
        } catch (Exception e) {
            return "";
        }
    }
}
