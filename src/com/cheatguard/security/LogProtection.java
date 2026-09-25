package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Keeps sealed session logs out of reach of Windows Explorer.
 *
 * <p>A sealed log is only evidence if it survives. Once a session ends, the
 * elevated helper that is already running for the network lockdown re-owns the
 * {@code .vault} and {@code .vault.sig} files to the Administrators group, drops
 * inherited permissions and leaves the signed-in account with <em>read</em> access
 * only. A student — or anyone using the desktop normally — then cannot delete,
 * rename or edit them: Explorer refuses, and because the account no longer owns the
 * files it cannot grant itself permission back either.
 *
 * <p>Deleting a log stays possible, but only the intended way: through the admin
 * dashboard, after the administrator password, which then asks Windows for elevation.
 *
 * <p>Boundary worth stating: a machine administrator who deliberately elevates can
 * always override file permissions. What this removes is deletion by a standard
 * user, by accident, or by anyone poking around in the folder.
 */
public final class LogProtection {

    private static final String REQUEST = "protect.request";
    private static final String DONE = "protect.done";

    private LogProtection() {
    }

    public static File requestFile() {
        return new File(AppPaths.getNetworkDirectory(), REQUEST);
    }

    public static File doneFile() {
        return new File(AppPaths.getNetworkDirectory(), DONE);
    }

    /**
     * Ask the running elevated helper to protect the given files.
     *
     * <p>Must be called while the session's lockdown helper is still alive, which is
     * why sealing happens before the network state is restored.
     *
     * @return true when the helper confirmed, false if it did not answer in time
     */
    public static boolean protectViaHelper(List<File> files) {
        List<File> existing = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.isFile()) existing.add(f);
        }
        if (existing.isEmpty()) return true;

        try {
            File done = doneFile();
            done.delete();
            StringBuilder sb = new StringBuilder();
            for (File f : existing) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            Files.writeString(requestFile().toPath(), sb.toString(), StandardCharsets.UTF_8);

            long deadline = System.currentTimeMillis() + 20_000L;
            while (System.currentTimeMillis() < deadline) {
                if (done.exists()) {
                    done.delete();
                    return true;
                }
                Thread.sleep(200L);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // fall through: the log is still written, just not permission-hardened
        }
        return false;
    }

    /**
     * Delete protected log files with a single elevation prompt.
     *
     * @return true if Windows accepted the elevated delete request
     */
    public static boolean deleteElevated(List<File> files) {
        List<File> targets = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.exists()) targets.add(f);
        }
        if (targets.isEmpty()) return true;

        Path list = null;
        try {
            StringBuilder sb = new StringBuilder();
            for (File f : targets) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            list = Files.createTempFile("cheatguard-delete-", ".txt");
            Files.writeString(list, sb.toString(), StandardCharsets.UTF_8);

            // The path list travels in a file so no quoting survives into PowerShell.
            String inner = "$l='" + list.toAbsolutePath().toString().replace("'", "''") + "';"
                    + "foreach($p in Get-Content -LiteralPath $l){"
                    + "if($p.Trim()){"
                    + "takeown /F \\\"$p\\\" /A | Out-Null;"
                    + "icacls \\\"$p\\\" /grant *S-1-5-32-544:(F) | Out-Null;"
                    + "Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}};"
                    + "Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue";

            String outer = "$ErrorActionPreference='Stop';"
                    + "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs "
                    + "-WindowStyle Hidden -PassThru -Wait "
                    + "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',\"" + inner + "\";"
                    + "if($null -eq $p){ throw 'not started' }";

            Process p = new ProcessBuilder("powershell.exe", "-NoProfile",
                    "-ExecutionPolicy", "Bypass", "-Command", outer)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            if (list != null) {
                try {
                    Files.deleteIfExists(list);
                } catch (Exception ignored) {
                    // the elevated step removes it as well
                }
            }
        }
    }
}
