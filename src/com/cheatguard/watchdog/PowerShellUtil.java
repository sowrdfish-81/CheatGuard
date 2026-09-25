package com.cheatguard.watchdog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Starts small read-only PowerShell probes without Windows command-line quote corruption. */
final class PowerShellUtil {
    private PowerShellUtil() {}

    static Process start(String script) throws IOException {
        String safeScript = "$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script;
        String encoded = Base64.getEncoder().encodeToString(safeScript.getBytes(StandardCharsets.UTF_16LE));
        ProcessBuilder pb = new ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                "-EncodedCommand", encoded);
        // Probe output is machine-readable. Never mix PowerShell diagnostics into it.
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        return pb.start();
    }
}
