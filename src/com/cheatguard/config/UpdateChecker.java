package com.cheatguard.config;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Checks GitHub for a newer Cheat.Guard release and, when asked, downloads the
 * official installer. The check is a plain HTTPS GET against the releases API;
 * the download always comes from this project's own release page.
 */
public final class UpdateChecker {

    public static final String CURRENT_VERSION = "3.0";
    private static final String RELEASES_API =
            "https://api.github.com/repos/sowrdfish-81/CheatGuard/releases/latest";

    /** A newer release: version string plus the installer's download URL. */
    public record UpdateInfo(String version, String downloadUrl) {}

    /**
     * Ask GitHub which release is latest. Returns empty when this build is current,
     * when the check cannot run (offline) or when the answer is malformed.
     */
    public static Optional<UpdateInfo> checkLatest() {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(RELEASES_API).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestProperty("User-Agent", "CheatGuard-Updater");
            c.setRequestProperty("Accept", "application/vnd.github+json");
            int code = c.getResponseCode();
            if (code != 200) return Optional.empty();
            String body;
            try (InputStream in = c.getInputStream()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            String tag = extract(body, "\"tag_name\":", "\"");
            if (tag == null || tag.isBlank()) return Optional.empty();
            String version = tag.replaceFirst("(?i)^v", "").trim();
            if (compareVersions(version, CURRENT_VERSION) <= 0) return Optional.empty();

            // Find the installer asset on that release.
            int assets = body.indexOf("\"assets\"");
            String downloadUrl = null;
            if (assets >= 0) {
                String rest = body.substring(assets);
                if (rest.contains("\"name\": \"CheatGuard-Setup.exe\"")
                        || rest.contains("\"name\":\"CheatGuard-Setup.exe\"")) {
                    downloadUrl = extract(rest, "\"browser_download_url\":", "\"");
                }
            }
            if (downloadUrl == null) return Optional.empty();
            return Optional.of(new UpdateInfo(version, downloadUrl));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Download the installer to the given destination, reporting progress as
     * whole percentage points through the callback.
     */
    public static void download(String url, File dest, java.util.function.IntConsumer progress)
            throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(10000);
        c.setReadTimeout(30000);
        c.setRequestProperty("User-Agent", "CheatGuard-Updater");
        long total = c.getContentLengthLong();
        try (InputStream in = c.getInputStream();
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buffer = new byte[65536];
            long done = 0;
            int lastPct = -1;
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                done += read;
                if (total > 0 && progress != null) {
                    int pct = (int) (done * 100 / total);
                    if (pct != lastPct) { lastPct = pct; progress.accept(pct); }
                }
            }
        }
    }

    /** Numeric compare of dotted versions ("2.2" vs "3.0"); non-numeric parts ignored. */
    static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int va = part(pa, i);
            int vb = part(pb, i);
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int part(String[] parts, int i) {
        if (i >= parts.length) return 0;
        try {
            return Integer.parseInt(parts[i].trim());
        } catch (Exception e) {
            return 0;
        }
    }

    /** First quoted string after a JSON key. */
    private static String extract(String json, String key, String ignored) {
        int at = json.indexOf(key);
        if (at < 0) return null;
        int q1 = json.indexOf('"', at + key.length());
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    private UpdateChecker() {
    }
}
