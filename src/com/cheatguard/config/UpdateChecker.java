package com.cheatguard.config;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.net.URI;

/**
 * Checks GitHub for a newer Cheat.Guard release and, when asked, downloads the
 * official installer. The check is a plain HTTPS GET against the releases API;
 * the download always comes from this project's own release page.
 */
public final class UpdateChecker {

    public static final String CURRENT_VERSION = "3.3";
    private static final String RELEASES_API =
            "https://api.github.com/repos/sowrdfish-81/CheatGuard/releases/latest";

    /** A newer release: version string plus the installer's download URL. */
    public record UpdateInfo(String version, String downloadUrl) {}

    /**
     * Ask GitHub which release is latest. Returns empty when this build is current,
     * when the check cannot run (offline) or when the answer is malformed.
     */
    public static Optional<UpdateInfo> checkLatest() {
        return checkLatestAgainst(CURRENT_VERSION);
    }

    /** Same check against an arbitrary version - lets tests verify the API. */
    static Optional<UpdateInfo> checkLatestAgainst(String currentVersion) {
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
            if (compareVersions(version, currentVersion) <= 0) return Optional.empty();

            // Find the installer asset on that release.
            String downloadUrl = findInstallerDownloadUrl(body);
            if (downloadUrl == null) return Optional.empty();
            if (!isTrustedDownloadUrl(downloadUrl)) return Optional.empty();
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
        if (!isTrustedDownloadUrl(url)) throw new SecurityException("Untrusted update URL");
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

    /**
     * Background update watcher: checks GitHub 15 seconds after the app starts and
     * then every 6 hours. When a newer release exists, the callback fires ONCE
     * (the UI decides whether to prompt - and never during a live session).
     */
    public static void startAutoChecking(java.util.function.Consumer<UpdateInfo> onNew) {
        java.util.concurrent.ScheduledExecutorService ses =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "CheatGuard-UpdateCheck");
                    t.setDaemon(true);
                    return t;
                });
        ses.scheduleWithFixedDelay(() -> {
            try {
                Optional<UpdateInfo> info = checkLatest();
                if (info.isPresent()) {
                    ses.shutdown();
                    onNew.accept(info.get());
                }
            } catch (Exception ignored) {
            }
        }, 15, 360, java.util.concurrent.TimeUnit.SECONDS);
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

    /** Select the URL belonging to the exact installer asset object. */
    static String findInstallerDownloadUrl(String json) {
        int assets = json.indexOf("\"assets\"");
        if (assets < 0) return null;
        int arrayStart = json.indexOf('[', assets);
        if (arrayStart < 0) return null;
        boolean inString = false;
        boolean escaped = false;
        int depth = 0;
        int objectStart = -1;
        for (int i = arrayStart + 1; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (inString) {
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == '"') inString = false;
                continue;
            }
            if (ch == '"') { inString = true; continue; }
            if (ch == '{') {
                if (depth == 0) objectStart = i;
                depth++;
            } else if (ch == '}' && depth > 0) {
                depth--;
                if (depth == 0 && objectStart >= 0) {
                    String object = json.substring(objectStart, i + 1);
                    String name = extract(object, "\"name\":", "\"");
                    if ("CheatGuard-Setup.exe".equals(name)) {
                        return extract(object, "\"browser_download_url\":", "\"");
                    }
                    objectStart = -1;
                }
            } else if (ch == ']' && depth == 0) {
                break;
            }
        }
        return null;
    }

    static boolean isTrustedDownloadUrl(String value) {
        try {
            URI uri = URI.create(value);
            String host = uri.getHost();
            return "https".equalsIgnoreCase(uri.getScheme())
                    && ("github.com".equalsIgnoreCase(host)
                    || "objects.githubusercontent.com".equalsIgnoreCase(host));
        } catch (Exception e) {
            return false;
        }
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
