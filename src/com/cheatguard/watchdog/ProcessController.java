package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;

/** Windows process enforcement helper. */
public class ProcessController {
    public boolean terminate(long pid) {
        if (pid <= 0) return false;
        try {
            ProcessBuilder pb = new ProcessBuilder("taskkill", "/PID", Long.toString(pid), "/T", "/F");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            int code = p.waitFor();
            return code == 0;
        } catch (Exception e) {
            AppLog.warn("Could not terminate PID " + pid + ": " + e.getMessage());
            return false;
        }
    }
}
