package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.util.Locale;

/**
 * Decides whether a denied website lookup is a real student violation.
 *
 * <p>A browser and Windows itself generate a constant stream of update, telemetry
 * and connectivity lookups. Those stay blocked, but turning each one into a
 * RED-flag row would bury the events that matter. This class filters that noise
 * and confirms the student is actually looking at an unapproved page in a
 * foreground browser before a violation is raised.
 */
final class WebsiteViolationReporter {

    private final SiteMonitor siteMonitor = new SiteMonitor();
    private final ProcessWhitelist processWhitelist = new ProcessWhitelist();

    private volatile long foregroundCacheAt;
    private volatile String foregroundCacheHost = "";
    private volatile boolean foregroundCacheBrowser;
    private volatile boolean foregroundCacheAllowed;

    /**
     * Map a denied host to the host that should be reported as a RED violation.
     *
     * @return the user-facing host, or {@code null} when the denial is background
     *         traffic that should not be reported
     */
    String userFacingViolation(String host) {
        String key = normalizeHost(host);
        if (key.isEmpty() || isBackgroundNoiseHost(key)) return null;
        return foregroundUnauthorizedHost(key);
    }

    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h.startsWith("www.") ? h.substring(4) : h;
    }

    /**
     * The unapproved website the student is actually looking at, or null when the
     * foreground is not a supported browser or is already on an approved page. A
     * short cache avoids spawning a PowerShell probe for every lookup in the same
     * navigation burst.
     */
    private String foregroundUnauthorizedHost(String blockedHost) {
        long now = System.currentTimeMillis();
        if (now - foregroundCacheAt > 900L) {
            String host = "";
            boolean browser = false;
            boolean allowedPage = false;
            try {
                ProcessInfo fg = siteMonitor.getForegroundWindow();
                browser = fg != null && processWhitelist.isBrowser(fg.getName());
                if (browser) {
                    host = AppConfig.normalizeSite(fg.getBrowserUrl());
                    allowedPage = siteMonitor.isAllowedBrowserPage(fg);
                }
            } catch (Exception ignored) {
                // treat a failed probe as "not a foreground browser"
            }
            foregroundCacheHost = host;
            foregroundCacheBrowser = browser;
            foregroundCacheAllowed = allowedPage;
            foregroundCacheAt = now;
        }

        if (!foregroundCacheBrowser) return null;
        if (foregroundCacheAllowed) return null;
        if (!foregroundCacheHost.isEmpty()) return foregroundCacheHost;

        // Address bar not exposed and the title does not identify an approved page.
        return blockedHost;
    }

    /** Known browser/Windows background endpoints that are not student violations. */
    static boolean isBackgroundNoiseHost(String host) {
        String h = normalizeHost(host);
        if (h.isEmpty()) return true;

        // Discord background gateway/CDN/status traffic (discord.com itself is NOT suppressed).
        if (h.equals("gateway.discord.gg") || h.endsWith(".gateway.discord.gg")
                || (h.startsWith("gateway-") && h.endsWith(".discord.gg"))
                || h.equals("status.discord.com") || h.equals("cdn.discordapp.com")
                || h.equals("media.discordapp.net")) return true;

        // Chromium/Google update, optimization and connectivity background services.
        if (h.equals("update.googleapis.com") || h.equals("clientservices.googleapis.com")
                || h.equals("optimizationguide-pa.googleapis.com") || h.equals("safebrowsing.googleapis.com")
                || h.equals("redirector.gvt1.com") || h.equals("clients2.google.com")
                || h.equals("clients4.google.com") || h.equals("connectivitycheck.gstatic.com")) return true;

        // Windows/Edge/OneDrive telemetry and push-notification background services.
        if (h.equals("mobile.events.data.microsoft.com") || h.endsWith(".events.data.microsoft.com")
                || h.equals("skydrive.wns.windows.com") || h.endsWith(".wns.windows.com")
                || h.equals("edge.microsoft.com") || h.equals("msedge.api.cdp.microsoft.com")) return true;

        // Name-resolution plumbing that is never a browsed website.
        if (h.equals("wpad") || h.startsWith("wpad.") || h.endsWith(".local")
                || h.endsWith(".arpa") || h.equals("localhost")) return true;

        return false;
    }
}
