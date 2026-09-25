package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Strict application allowlist. Browsers are judged by website, not by process. */
public class ProcessWhitelist {

    /**
     * Cheat.Guard itself and the Windows shell. Task Manager is deliberately not here:
     * it is the obvious way to kill the invigilator app, so it is closed like any other
     * unapproved application unless an administrator adds it to the allowlist.
     */
    private static final Set<String> ALWAYS_ALLOWED = new HashSet<>(Arrays.asList(
            "cheatguard.exe", "explorer.exe"));

    private static final Set<String> BROWSERS = new HashSet<>(Arrays.asList(
            "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
            "opera.exe", "opera_gx.exe", "vivaldi.exe"));

    /**
     * Windows shell and platform components. These are never student applications,
     * so they are neither closed nor written to the audit log — listing them would
     * bury the events an invigilator actually needs to read.
     */
    private static final Set<String> SYSTEM_PROCESSES = new HashSet<>(Arrays.asList(
            // shell and desktop
            "explorer.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "taskhostw.exe",
            "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
            "searchapp.exe", "searchui.exe", "searchhost.exe", "textinputhost.exe",
            "applicationframehost.exe", "lockapp.exe", "widgets.exe", "widgetservice.exe",
            "systemsettings.exe", "useroobebroker.exe", "dllhost.exe", "wudfhost.exe",
            "fontdrvhost.exe", "csrss.exe", "winlogon.exe", "logonui.exe", "smartscreen.exe",
            // notifications, input, accessibility
            "shellhost.exe", "inputapp.exe", "narrator.exe", "magnify.exe", "osk.exe",
            // security and platform components that can surface a window
            "securityhealthsystray.exe", "securityhealthservice.exe", "mpcmdrun.exe",
            "msmpeng.exe", "nissrv.exe", "wermgr.exe", "werfault.exe", "sppsvc.exe",
            "backgroundtaskhost.exe", "phoneexperiencehost.exe", "yourphone.exe",
            "msedgewebview2.exe", "crashpad_handler.exe",
            // Windows update / Store plumbing
            "usoclient.exe", "mousocoreworker.exe", "tiworker.exe", "trustedinstaller.exe",
            "winstore.app.exe", "storeexperiencehost.exe",
            // editor platform helper that VS Code-class IDEs keep respawning
            "extensionhost.exe", "extension host.exe", "extension_host.exe"));

    public boolean isAllowed(String processName) {
        if (processName == null) return true;
        String p = processName.toLowerCase(Locale.ROOT);
        if (ALWAYS_ALLOWED.contains(p)) return true;
        if (SYSTEM_PROCESSES.contains(p)) return true;
        if (BROWSERS.contains(p)) return true;
        return AppConfig.getInstance().getAllowedProcesses().contains(p);
    }

    /** True for Windows components that must stay invisible in the audit log. */
    public boolean isSystemProcess(String processName) {
        if (processName == null) return true;
        String p = processName.toLowerCase(Locale.ROOT);
        return SYSTEM_PROCESSES.contains(p) || ALWAYS_ALLOWED.contains(p);
    }

    public boolean isBrowser(String processName) {
        return processName != null && BROWSERS.contains(processName.toLowerCase(Locale.ROOT));
    }

    /** "codeblocks.exe" becomes "Codeblocks", for log rows an invigilator reads. */
    public static String friendlyName(String processName) {
        if (processName == null || processName.isBlank()) return "Unknown app";
        String n = processName.trim();
        if (n.toLowerCase(Locale.ROOT).endsWith(".exe")) n = n.substring(0, n.length() - 4);
        n = n.replace('_', ' ').replace('-', ' ').trim();
        if (n.isEmpty()) return "Unknown app";
        return Character.toUpperCase(n.charAt(0)) + n.substring(1);
    }
}
