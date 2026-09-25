package com.cheatguard.config;

import com.cheatguard.core.AppLog;

import java.io.*;
import java.net.IDN;
import java.net.URI;
import java.util.*;

/** Persistent strict allow-lists edited from the admin GUI. */
public class AppConfig {

    /**
     * Defaults a fresh install (and an older config, once) starts from: the tools a
     * competitive-programming contest or coding test needs. Admins can remove any of
     * them per exam; the marker below keeps a later launch from re-adding removed ones.
     */
    private static final String[] DEFAULT_PROCESSES = {
            // editors and IDEs
            "code.exe", "codeblocks.exe", "notepad.exe", "notepad++.exe", "sublime_text.exe",
            "devcpp.exe", "idea64.exe", "clion64.exe",
            // compilers, linkers and build tools
            "gcc.exe", "g++.exe", "cc.exe", "c++.exe", "cpp.exe", "mingw32-gcc.exe",
            "mingw32-g++.exe", "as.exe", "ld.exe", "make.exe", "mingw32-make.exe",
            "cmake.exe", "gdb.exe",
            // the default output name of a g++/gcc build
            "a.exe",
            // language runtimes and terminals
            "java.exe", "javac.exe", "javaw.exe", "python.exe", "pythonw.exe", "py.exe",
            "node.exe", "git.exe", "bash.exe",
            "cmd.exe", "powershell.exe", "wt.exe", "windowsterminal.exe",
            "conhost.exe", "openconsole.exe",
    };

    private static final String[] DEFAULT_SITES = {
            // contest judges
            "codeforces.com", "atcoder.jp", "codechef.com", "leetcode.com",
            "hackerrank.com", "hackerearth.com", "topcoder.com", "cses.fi",
            "spoj.com", "vjudge.net", "lightoj.com", "beecrowd.com", "toph.co",
            // Google sign-in, search and page assets used by the judges
            "google.com", "accounts.google.com", "gstatic.com", "googleusercontent.com",
    };

    /** Bump when the default lists change; missing defaults are merged in once per version. */
    private static final String DEFAULTS_VERSION = "2";

    private static AppConfig instance;
    private final File configFile = AppPaths.getWhitelistFile();
    private final Set<String> allowedProcesses = new TreeSet<>();
    private final Set<String> allowedSites = new TreeSet<>();
    /** Executable name to full launch path, for apps the admin picked from disk. */
    private final Map<String, String> processPaths = new TreeMap<>();

    private AppConfig() { load(); }

    public static synchronized AppConfig getInstance() {
        if (instance == null) instance = new AppConfig();
        return instance;
    }

    private void load() {
        Properties props = new Properties();
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                props.load(fis);
            } catch (IOException e) {
                AppLog.warn("Could not read config: " + e.getMessage());
            }
        }
        String procs = props.getProperty("allowed.processes", "");
        String sites = props.getProperty("allowed.sites", "");
        for (String p : procs.split(",")) if (!p.trim().isEmpty()) allowedProcesses.add(normalizeProcess(p));
        for (String s : sites.split(",")) {
            String normalized = normalizeSite(s);
            if (!normalized.isEmpty()) allowedSites.add(normalized);
        }
        // Launch paths are stored as "name.exe|C:\path\name.exe" entries.
        for (String entry : props.getProperty("allowed.process.paths", "").split("\\|\\|")) {
            int bar = entry.indexOf('|');
            if (bar <= 0) continue;
            String name = normalizeProcess(entry.substring(0, bar));
            String path = entry.substring(bar + 1).trim();
            if (!name.isEmpty() && !path.isEmpty()) processPaths.put(name, path);
        }
        // One-time merge of a new default set into an existing configuration; after
        // this the marker is current, so entries an admin removed stay removed.
        boolean merged = false;
        if (!DEFAULTS_VERSION.equals(props.getProperty("allowlist.defaults.version", "1"))) {
            for (String p : DEFAULT_PROCESSES) {
                if (allowedProcesses.add(normalizeProcess(p))) merged = true;
            }
            for (String s : DEFAULT_SITES) {
                String normalized = normalizeSite(s);
                if (!normalized.isEmpty() && allowedSites.add(normalized)) merged = true;
            }
        }
        if (!configFile.exists() || merged) save();
    }

    public synchronized void save() {
        Properties props = new Properties();
        props.setProperty("allowlist.defaults.version", DEFAULTS_VERSION);
        props.setProperty("allowed.processes", String.join(",", allowedProcesses));
        props.setProperty("allowed.sites", String.join(",", allowedSites));
        StringBuilder paths = new StringBuilder();
        for (Map.Entry<String, String> e : processPaths.entrySet()) {
            if (paths.length() > 0) paths.append("||");
            paths.append(e.getKey()).append('|').append(e.getValue());
        }
        props.setProperty("allowed.process.paths", paths.toString());
        try {
            File parent = configFile.getParentFile();
            if (parent != null) parent.mkdirs();
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                props.store(fos, "Cheat.Guard - strict allowlists");
            }
        } catch (IOException e) {
            AppLog.warn("Could not save config: " + e.getMessage());
        }
    }

    /** Full launch path for an allowed app, or null when only its name is known. */
    public synchronized String getProcessPath(String name) {
        return processPaths.get(normalizeProcess(name));
    }

    /** Register an app from its full path so it can also be launched from the app. */
    public synchronized void addAllowedProcessPath(File executable) {
        if (executable == null) return;
        String name = normalizeProcess(executable.getName());
        if (name.isEmpty()) return;
        allowedProcesses.add(name);
        processPaths.put(name, executable.getAbsolutePath());
        save();
    }

    public synchronized Set<String> getAllowedProcesses() { return new TreeSet<>(allowedProcesses); }
    public synchronized Set<String> getAllowedSites() { return new TreeSet<>(allowedSites); }

    public synchronized void addAllowedProcess(String name) {
        String normalized = normalizeProcess(name);
        if (!normalized.isEmpty()) { allowedProcesses.add(normalized); save(); }
    }
    public synchronized void removeAllowedProcess(String name) {
        if (name != null) {
            String key = normalizeProcess(name);
            allowedProcesses.remove(key);
            processPaths.remove(key);
            save();
        }
    }
    public synchronized void addAllowedSite(String site) {
        if (site == null) return;
        // Accept pasted URLs or multiple domains, but persist only canonical host names.
        for (String part : site.split("[,;\\s]+")) {
            String normalized = normalizeSite(part);
            if (!normalized.isEmpty()) allowedSites.add(normalized);
        }
        save();
    }
    public synchronized void removeAllowedSite(String site) {
        if (site != null) { allowedSites.remove(normalizeSite(site)); save(); }
    }

    /** True for an allowed host itself and any of its subdomains. */
    public synchronized boolean isSiteAllowed(String hostOrUrl) {
        String host = normalizeSite(hostOrUrl);
        if (host.isEmpty()) return false;
        for (String allowed : allowedSites) {
            if (host.equals(allowed) || host.endsWith("." + allowed)) return true;
        }
        return false;
    }

    /** Canonical domain used by both the settings UI and the network proxy. */
    public static String normalizeSite(String value) {
        if (value == null) return "";
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (v.isEmpty()) return "";
        if (v.startsWith("*.")) v = v.substring(2);

        try {
            String candidate = v.matches("^[a-z][a-z0-9+.-]*://.*") ? v : "https://" + v;
            URI uri = new URI(candidate);
            String host = uri.getHost();
            if (host != null && !host.trim().isEmpty()) v = host;
            else {
                v = v.replaceFirst("^https?://", "");
                int slash = v.indexOf('/');
                if (slash >= 0) v = v.substring(0, slash);
                int q = v.indexOf('?');
                if (q >= 0) v = v.substring(0, q);
                int hash = v.indexOf('#');
                if (hash >= 0) v = v.substring(0, hash);
                int colon = v.lastIndexOf(':');
                if (colon > 0 && v.indexOf(':') == colon) v = v.substring(0, colon);
            }
        } catch (Exception ignored) {
            v = v.replaceFirst("^https?://", "");
            int slash = v.indexOf('/');
            if (slash >= 0) v = v.substring(0, slash);
            int colon = v.lastIndexOf(':');
            if (colon > 0 && v.indexOf(':') == colon) v = v.substring(0, colon);
        }

        v = v.replaceFirst("^www\\.", "");
        while (v.endsWith(".")) v = v.substring(0, v.length() - 1);
        try { v = IDN.toASCII(v); } catch (Exception ignored) {}
        // Require at least one dot and a letters-only TLD. Without this a bare entry
        // such as "com" would make isSiteAllowed() accept nearly every domain, because
        // matching also accepts subdomains of an allowed entry.
        return v.matches("([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}") ? v : "";
    }

    private String normalizeProcess(String value) {
        if (value == null) return "";
        String v = new File(value.trim()).getName().toLowerCase(Locale.ROOT);
        if (!v.isEmpty() && !v.contains(".") && !v.equals("system")) v += ".exe";
        return v;
    }
}
