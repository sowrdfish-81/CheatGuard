package com.cheatguard.config;

import com.cheatguard.core.AppLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Finds the programming tools a CS student needs - compilers, interpreters,
 * build tools, version control, lexer/parser generators - that are INSTALLED on
 * this machine, and adds them to the allowed list with their full paths so they
 * can run (and be relaunched) during an exam without any extra setup.
 *
 * <p>The scan runs once, on the first start after a scan-list change (a version
 * marker in the config), on a background thread: the PowerShell probe walks the
 * PATH plus the usual tool install roots and returns every match. Tool entries
 * are allowed processes but NOT "apps" - they never appear on the session
 * monitor's launch combo, which lists only what the invigilator added.
 */
public final class ToolchainScanner {

    /** Bump when the probed tool list or install roots change. */
    public static final String SCAN_VERSION = "2";

    private static final String MARKER_KEY = "toolchain.scan.version";

    /** Every tool name probed, by stem (without .exe). */
    private static final String[] TOOL_NAMES = {
            // C / C++ toolchain
            "gcc", "g++", "cc", "c++", "clang", "clang++", "clang-format",
            "mingw32-gcc", "mingw32-g++", "make", "mingw32-make", "cmake",
            "ninja", "gdb", "ld", "as", "nasm", "ar", "objdump",
            // lexer / parser generators (lex & friends)
            "flex", "win_flex", "lex", "bison", "win_bison", "yacc", "byacc",
            // Java
            "java", "javac", "javaw", "jar", "jshell",
            // Python
            "python", "python3", "pythonw", "py", "pip",
            // JS / web
            "node", "npm", "npx",
            // VCS / shell
            "git", "bash", "sh", "cmd", "powershell", "wt",
            // other languages a CS curriculum touches
            "rustc", "cargo", "go", "ghc", "dotnet", "sqlite3", "mysql", "psql"
    };

    private ToolchainScanner() {
    }

    /** Run the one-time scan on a background thread when the marker is stale. */
    public static void scanIfNeededAsync() {
        if (SCAN_VERSION.equals(AppConfig.getInstance().getConfigValue(MARKER_KEY))) return;
        Thread t = new Thread(() -> {
            try {
                int found = scanNow();
                AppConfig.getInstance().setConfigValue(MARKER_KEY, SCAN_VERSION);
                AppLog.info("Toolchain scan allowed " + found + " installed tools.");
            } catch (Exception e) {
                AppLog.warn("Toolchain scan failed: " + e.getMessage());
            }
        }, "CheatGuard-ToolchainScan");
        t.setDaemon(true);
        t.start();
    }

    /** Probe the machine and allow every tool found. Returns how many were added. */
    static synchronized int scanNow() {
        Set<String> paths = new LinkedHashSet<>();
        try {
            // NO double quotes anywhere in this script: Java's ProcessBuilder
            // escapes embedded quotes in a way PowerShell's -Command parsing eats,
            // which unquoted the paths and made the whole probe a parse error
            // (the "0 tools installed" failure). Env-var paths use + concatenation.
            String nameList = String.join("','", TOOL_NAMES);
            String script =
                    "$names = @('" + nameList + "'); " +
                    "foreach ($n in $names) { " +
                    "  $c = Get-Command $n -ErrorAction SilentlyContinue; " +
                    "  if ($c -and $c.Source) { Write-Output $c.Source } " +
                    "} " +
                    "$pf = $env:ProgramFiles; " +
                    "$pf86 = ${env:ProgramFiles(x86)}; " +
                    "$dirs = @(" +
                    "  ($pf + '\\Java'), ($pf + '\\Eclipse Adoptium'), ($pf86 + '\\Java')," +
                    "  'C:\\MinGW\\bin', 'C:\\MinGW64\\bin', 'C:\\TDM-GCC-64\\bin', 'C:\\TDM-GCC-32\\bin'," +
                    "  'C:\\Strawberry\\c\\bin', 'C:\\GnuWin32\\bin', ($pf + '\\LLVM\\bin')," +
                    "  ($pf + '\\Git\\bin'), ($pf + '\\Git\\cmd'), ($pf + '\\nodejs')," +
                    "  ($pf + '\\CodeBlocks\\MinGW\\bin'), ($env:LOCALAPPDATA + '\\Programs\\Python')); " +
                    "foreach ($d in $dirs) { " +
                    "  if (-not $d) { continue } " +
                    "  if (-not (Test-Path $d)) { continue } " +
                    "  Get-ChildItem -Path $d -Recurse -Depth 2 -Filter *.exe -ErrorAction SilentlyContinue | " +
                    "  ForEach-Object { $stem = $_.BaseName.ToLower(); " +
                    "    if ($names -contains $stem) { Write-Output $_.FullName } } }";
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                    "-WindowStyle", "Hidden", "-Command", script)
                    .redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String v = line.trim();
                    if (v.length() > 4 && v.toLowerCase().endsWith(".exe")) paths.add(v);
                }
            }
            p.waitFor(90, java.util.concurrent.TimeUnit.SECONDS);
            if (p.isAlive()) p.destroyForcibly();
        } catch (Exception e) {
            AppLog.warn("Toolchain probe error: " + e.getMessage());
        }

        int added = 0;
        for (String path : paths) {
            File exe = new File(path);
            if (exe.isFile()) {
                AppConfig.getInstance().addAllowedProcessPath(exe);
                added++;
            }
        }
        return added;
    }
}
