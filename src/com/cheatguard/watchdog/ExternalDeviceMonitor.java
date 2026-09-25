package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Detects USB storage, USB network/Wi-Fi adapters and portable data devices. */
public class ExternalDeviceMonitor {
    private static final Set<String> VALID_TYPES = new HashSet<>(Arrays.asList(
            "USB_STORAGE", "USB_NETWORK", "PORTABLE_DEVICE"));

    private final Map<String, String> known = new LinkedHashMap<>();

    public ExternalDeviceMonitor() { known.putAll(snapshot()); }

    /** Devices that were already connected before monitoring started. */
    public synchronized List<String> getPresentRiskDevices() {
        return new ArrayList<>(known.values());
    }

    /** Devices attached after the initial snapshot. */
    public synchronized List<String> checkForNewRiskDevices() {
        Map<String, String> current = snapshot();
        List<String> added = new ArrayList<>();
        for (Map.Entry<String, String> e : current.entrySet()) {
            if (!known.containsKey(e.getKey())) added.add(e.getValue());
        }
        known.clear();
        known.putAll(current);
        return added;
    }

    private Map<String, String> snapshot() {
        Map<String, String> devices = new LinkedHashMap<>();
        try {
            String cmd =
                    "Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'} | ForEach-Object { 'USB_STORAGE@@@' + $_.PNPDeviceID + '@@@' + $_.Model };" +
                    "Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.PNPDeviceID -like 'USB*'} | ForEach-Object { 'USB_NETWORK@@@' + $_.PNPDeviceID + '@@@' + $_.Name };" +
                    "if(Get-Command Get-PnpDevice -ErrorAction SilentlyContinue){ Get-PnpDevice -PresentOnly -Class WPD | ForEach-Object { 'PORTABLE_DEVICE@@@' + $_.InstanceId + '@@@' + $_.FriendlyName } }";
            Process p = PowerShellUtil.start(cmd);
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String[] parts = line.split("@@@", 3);
                    if (parts.length != 3) continue;
                    String type = parts[0].trim();
                    String id = parts[1].trim();
                    String name = cleanName(parts[2]);
                    if (!VALID_TYPES.contains(type) || !looksLikeDeviceId(id) || looksLikePowerShellNoise(name)) continue;
                    devices.put(type + "|" + id, friendlyType(type) + ": " + name);
                }
            }
            p.waitFor();
        } catch (Exception e) {
            AppLog.warn("External device scan error: " + e.getMessage());
        }
        return devices;
    }

    private boolean looksLikeDeviceId(String id) {
        if (id == null) return false;
        String s = id.trim();
        if (s.length() < 3 || s.length() > 600) return false;
        if (s.contains("$(") || s.contains("@@@") || s.contains("CommandNotFoundException")) return false;
        return s.contains("\\") || s.toUpperCase(Locale.ROOT).startsWith("USB") || s.toUpperCase(Locale.ROOT).startsWith("SWD");
    }

    private boolean looksLikePowerShellNoise(String value) {
        if (value == null) return true;
        String s = value.toLowerCase(Locale.ROOT);
        return s.contains("commandnotfoundexception") || s.contains("not recognized as the name") ||
                s.contains("the term '") || s.contains("categoryinfo") || s.contains("fullyqualifiederrorid") || s.contains("$(");
    }

    private String friendlyType(String type) {
        if ("USB_STORAGE".equals(type)) return "USB storage";
        if ("USB_NETWORK".equals(type)) return "USB network adapter";
        if ("PORTABLE_DEVICE".equals(type)) return "Portable device";
        return "External device";
    }

    private String cleanName(String value) {
        String v = value == null ? "" : value.trim();
        return v.isEmpty() ? "Unknown device" : v.replaceAll("\\s+", " ");
    }
}
