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

    /** Fresh installs start with NO websites allowed: the invigilator adds the
     *  exam sites one by one. Apps for coding tests and labs DO ship allowed. */
    private static final String[] DEFAULT_SITES = {};

    /** Login/mail sites removed from the defaults in version 3. */
    private static final Set<String> REMOVED_IN_V3 = Set.of("accounts.google.com", "gmail.com");

    /** The site defaults of versions 1-3, removed from existing configs in version 4
     *  so every exam starts with an empty site list (admins add what they need). */
    private static final Set<String> REMOVED_IN_V4 = Set.of(
            "codeforces.com", "atcoder.jp", "codechef.com", "leetcode.com", "hackerrank.com",
            "hackerearth.com", "topcoder.com", "cses.fi", "spoj.com", "vjudge.net",
            "lightoj.com", "beecrowd.com", "toph.co", "gstatic.com", "googleusercontent.com",
            "ssl.gstatic.com", "google.com", "accounts.google.com", "gmail.com");

    /** Bump when the default lists change; missing defaults are merged in once per version. */
    private static final String DEFAULTS_VERSION = "4";

    private static AppConfig instance;
    private final File configFile = AppPaths.getWhitelistFile();
    private final Set<String> allowedProcesses = new TreeSet<>();
    private final Set<String> allowedSites = new TreeSet<>();
    /** Executable name to full launch path, for apps the admin picked from disk. */
    private final Map<String, String> processPaths = new TreeMap<>();
    /** Executable name to the app's real (marketing) name, e.g. code.exe -> Visual Studio Code. */
    private final Map<String, String> displayNames = new TreeMap<>();
    /** Executable name to the launch arguments its Start-Menu shortcut carries,
     *  e.g. update.exe -> "--processStart Discord.exe" (Squirrel-style launchers). */
    private final Map<String, String> processArgs = new TreeMap<>();
    /** Executables the INVIGILATOR added as "apps" (search picker / Choose .exe).
     *  Only these appear on the session monitor's launch combo - toolchain entries
     *  (compilers, git, cmd...) are allowed to run but are not launchable apps. */
    private final Set<String> appEntries = new TreeSet<>();
    /** Generic markers and flags persisted as-is (scan versions, timestamps). */
    private final Map<String, String> configValues = new TreeMap<>();

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
        // Real app names: appname.code.exe=Visual Studio Code
        for (String key : props.stringPropertyNames()) {
            if (key.startsWith("appname.")) {
                String exe = normalizeProcess(key.substring(8));
                String display = props.getProperty(key, "").trim();
                if (!exe.isEmpty() && !display.isEmpty()) displayNames.put(exe, display);
            } else if (key.startsWith("appargs.")) {
                String exe = normalizeProcess(key.substring(8));
                String args = props.getProperty(key, "").trim();
                if (!exe.isEmpty() && !args.isEmpty()) processArgs.put(exe, args);
            }
        }
        // Invigilator-added apps. Old configs predate the list: seed it with every
        // process that has a stored launch path (only picker-added apps have one).
        String apps = props.getProperty("allowed.apps");
        if (apps == null) {
            appEntries.addAll(processPaths.keySet());
        } else {
            for (String a : apps.split(",")) {
                String n = normalizeProcess(a);
                if (!n.isEmpty()) appEntries.add(n);
            }
        }
        for (String key : props.stringPropertyNames()) {
            if (key.startsWith("cfg.")) configValues.put(key.substring(4), props.getProperty(key, ""));
        }
        // One-time merge of a new default set into an existing configuration; after
        // this the marker is current, so entries an admin removed stay removed.
        // Version 3 also REMOVES the account/login sites from the defaults.
        boolean merged = false;
        if (!DEFAULTS_VERSION.equals(props.getProperty("allowlist.defaults.version", "1"))) {
            for (String p : DEFAULT_PROCESSES) {
                if (allowedProcesses.add(normalizeProcess(p))) merged = true;
            }
            for (String s : DEFAULT_SITES) {
                String normalized = normalizeSite(s);
                if (!normalized.isEmpty() && allowedSites.add(normalized)) merged = true;
            }
            for (String gone : REMOVED_IN_V3) {
                if (allowedSites.remove(normalizeSite(gone))) merged = true;
            }
            for (String gone : REMOVED_IN_V4) {
                if (allowedSites.remove(normalizeSite(gone))) merged = true;
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
        for (Map.Entry<String, String> e : displayNames.entrySet()) {
            props.setProperty("appname." + e.getKey(), e.getValue());
        }
        for (Map.Entry<String, String> e : processArgs.entrySet()) {
            props.setProperty("appargs." + e.getKey(), e.getValue());
        }
        props.setProperty("allowed.apps", String.join(",", appEntries));
        for (Map.Entry<String, String> e : configValues.entrySet()) {
            props.setProperty("cfg." + e.getKey(), e.getValue());
        }
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

    /** Store the app's real (marketing) name shown in lists and logs. */
    public synchronized void setAppDisplayName(String exeName, String displayName) {
        String key = normalizeProcess(exeName);
        if (key.isEmpty() || displayName == null || displayName.isBlank()) return;
        displayNames.put(key, displayName.trim());
        save();
    }

    /** The app's real name when known, or null to fall back to the exe name. */
    public synchronized String getAppDisplayName(String exeName) {
        if (exeName == null) return null;
        return displayNames.get(normalizeProcess(exeName));
    }

    /** Store the launch arguments the app's own shortcut carries (e.g. Squirrel launchers). */
    public synchronized void setProcessArgs(String exeName, String args) {
        String key = normalizeProcess(exeName);
        if (key.isEmpty() || args == null || args.isBlank()) return;
        processArgs.put(key, args.trim());
        save();
    }

    /** The launch arguments stored for an app from its shortcut, or null. */
    public synchronized String getProcessArgs(String exeName) {
        if (exeName == null) return null;
        return processArgs.get(normalizeProcess(exeName));
    }

    /** Register an executable as an invigilator-added APP (shown on the monitor combo). */
    public synchronized void addAppEntry(String exeName) {
        String key = normalizeProcess(exeName);
        if (!key.isEmpty() && appEntries.add(key)) save();
    }

    /** Invigilator-added apps only - the session monitor launches from this list. */
    public synchronized Set<String> getAppEntries() { return new TreeSet<>(appEntries); }

    // --------------------------------------------------------- exam profiles

    private static String profileKey(String name) {
        String v = name == null ? "" : name.trim().replaceAll("[^A-Za-z0-9 _-]", "");
        return v.isEmpty() ? "" : v;
    }

    private static File profileFile(String key) {
        File dir = new File(AppPaths.getConfigDirectory(), "profiles");
        if (!dir.exists()) dir.mkdirs();
        return new File(dir, key + ".properties");
    }

    /**
     * Save the current exam setup - allowed sites plus the invigilator-added apps
     * (paths, display names, launch arguments) - under a name, so the next exam
     * with the same tools needs one click instead of re-adding everything.
     * Toolchain entries are machine-wide and are not part of a profile.
     */
    public synchronized boolean saveProfile(String name) {
        String key = profileKey(name);
        if (key.isEmpty()) return false;
        java.util.Properties p = new java.util.Properties();
        p.setProperty("allowed.sites", String.join(",", allowedSites));
        p.setProperty("allowed.apps", String.join(",", appEntries));
        StringBuilder paths = new StringBuilder();
        for (String exe : appEntries) {
            String path = processPaths.get(exe);
            if (path != null) {
                if (paths.length() > 0) paths.append("||");
                paths.append(exe).append('|').append(path);
            }
        }
        p.setProperty("allowed.process.paths", paths.toString());
        for (String exe : appEntries) {
            String d = displayNames.get(exe);
            if (d != null) p.setProperty("appname." + exe, d);
            String a = processArgs.get(exe);
            if (a != null) p.setProperty("appargs." + exe, a);
        }
        try {
            java.io.File f = profileFile(key);
            if (!f.getParentFile().exists()) f.getParentFile().mkdirs();
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(f)) {
                p.store(fos, "Cheat.Guard exam profile: " + name);
            }
            return true;
        } catch (Exception e) {
            AppLog.warn("Could not save profile: " + e.getMessage());
            return false;
        }
    }

    /** Saved profile names, sorted. */
    public synchronized java.util.List<String> listProfiles() {
        java.util.List<String> out = new java.util.ArrayList<>();
        java.io.File dir = new File(AppPaths.getConfigDirectory(), "profiles");
        File[] files = dir.listFiles((d, n) -> n.toLowerCase(java.util.Locale.ROOT).endsWith(".properties"));
        if (files != null) {
            for (File f : files) out.add(f.getName().replaceFirst("\\.properties$", ""));
        }
        java.util.Collections.sort(out);
        return out;
    }

    /**
     * Load a profile: replaces the allowed sites and the invigilator-added apps
     * with the profile's; machine-wide toolchain entries stay untouched.
     */
    public synchronized void loadProfile(String name) {
        String key = profileKey(name);
        if (key.isEmpty()) return;
        File f = profileFile(key);
        if (!f.isFile()) return;
        java.util.Properties p = new java.util.Properties();
        try (java.io.FileInputStream fis = new java.io.FileInputStream(f)) {
            p.load(fis);
        } catch (IOException e) {
            AppLog.warn("Could not read profile: " + e.getMessage());
            return;
        }

        allowedSites.clear();
        for (String s2 : p.getProperty("allowed.sites", "").split(",")) {
            String n = normalizeSite(s2);
            if (!n.isEmpty()) allowedSites.add(n);
        }

        // Remove only the invigilator-added apps; toolchain entries survive.
        for (String exe : new java.util.HashSet<>(appEntries)) {
            allowedProcesses.remove(exe);
            processPaths.remove(exe);
            displayNames.remove(exe);
            processArgs.remove(exe);
        }
        appEntries.clear();

        for (String entry : p.getProperty("allowed.process.paths", "").split("\\|\\|")) {
            int bar = entry.indexOf('|');
            if (bar <= 0) continue;
            String exe = normalizeProcess(entry.substring(0, bar));
            String path = entry.substring(bar + 1).trim();
            if (!exe.isEmpty() && !path.isEmpty()) {
                appEntries.add(exe);
                allowedProcesses.add(exe);
                processPaths.put(exe, path);
            }
        }
        for (String k : p.stringPropertyNames()) {
            if (k.startsWith("appname.")) {
                String exe = normalizeProcess(k.substring(8));
                String v = p.getProperty(k, "").trim();
                if (!exe.isEmpty() && !v.isEmpty()) { displayNames.put(exe, v); appEntries.add(exe); allowedProcesses.add(exe); }
            } else if (k.startsWith("appargs.")) {
                String exe = normalizeProcess(k.substring(8));
                String v = p.getProperty(k, "").trim();
                if (!exe.isEmpty() && !v.isEmpty()) { processArgs.put(exe, v); appEntries.add(exe); allowedProcesses.add(exe); }
            }
        }
        // Apps named but without a stored path still count as allowed by name.
        for (String exe : p.getProperty("allowed.apps", "").split(",")) {
            String n = normalizeProcess(exe);
            if (!n.isEmpty()) { appEntries.add(n); allowedProcesses.add(n); }
        }
        save();
    }

    public synchronized void deleteProfile(String name) {
        String key = profileKey(name);
        if (!key.isEmpty()) profileFile(key).delete();
    }

    /** Generic marker/flag storage (e.g. toolchain scan version). */
    public synchronized String getConfigValue(String key) {
        return configValues.get(key);
    }

    public synchronized void setConfigValue(String key, String value) {
        if (key == null || key.isBlank()) return;
        if (value == null || value.isBlank()) configValues.remove(key);
        else configValues.put(key, value);
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
            displayNames.remove(key);
            processArgs.remove(key);
            appEntries.remove(key);
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
