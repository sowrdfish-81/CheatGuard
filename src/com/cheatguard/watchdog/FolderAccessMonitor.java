package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Watches current File Explorer locations and reports access outside the per-student exam folder. */
public class FolderAccessMonitor {
    private final File allowedFolder;

    public FolderAccessMonitor(File allowedFolder) {
        this.allowedFolder = allowedFolder;
    }

    public List<String> getUnauthorizedExplorerFolders() {
        List<String> bad = new ArrayList<>();
        for (String path : getExplorerFolders()) {
            if (!isInsideAllowedFolder(path)) bad.add(path);
        }
        return bad;
    }

    private List<String> getExplorerFolders() {
        List<String> paths = new ArrayList<>();
        try {
            String cmd = "$s=New-Object -ComObject Shell.Application; $s.Windows() | ForEach-Object { try { if($_.FullName -match 'explorer.exe$' -and $_.LocationURL -like 'file:*'){ $_.LocationURL } } catch {} }";
            Process p = PowerShellUtil.start(cmd);
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || !line.toLowerCase().startsWith("file:")) continue;
                    try { paths.add(new File(new URI(line)).getCanonicalPath()); }
                    catch (Exception ignored) {}
                }
            }
            p.waitFor();
        } catch (Exception e) {
            AppLog.warn("Folder scan error: " + e.getMessage());
        }
        return paths;
    }

    private boolean isInsideAllowedFolder(String path) {
        try {
            String allowed = allowedFolder.getCanonicalPath();
            String target = new File(path).getCanonicalPath();
            return target.equalsIgnoreCase(allowed) || target.toLowerCase().startsWith((allowed + File.separator).toLowerCase());
        } catch (Exception e) { return false; }
    }
}
