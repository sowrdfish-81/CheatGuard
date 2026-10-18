package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Reads foreground browser URL via Windows UI Automation when possible, with title fallback. */
public class SiteMonitor {
    public ProcessInfo getForegroundWindow() {
        try {
            String ps =
                    "$sig='[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); [DllImport(\"user32.dll\")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);';" +
                    "Add-Type -MemberDefinition $sig -Name Win32 -Namespace Native -ErrorAction SilentlyContinue;" +
                    "$h=[Native.Win32]::GetForegroundWindow();$pid2=0;[Native.Win32]::GetWindowThreadProcessId($h,[ref]$pid2)|Out-Null;" +
                    "$p=Get-Process -Id $pid2 -ErrorAction SilentlyContinue;$url='';" +
                    "if($p){try{Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue;" +
                    "$root=[System.Windows.Automation.AutomationElement]::FromHandle($h);" +
                    "$cond=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty,[System.Windows.Automation.ControlType]::Edit);" +
                    "$edits=$root.FindAll([System.Windows.Automation.TreeScope]::Descendants,$cond);" +
                    "foreach($e in $edits){$n=$e.Current.Name;if($n -match '(?i)address|location|url'){try{$vp=$e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern);$v=$vp.Current.Value;if($v){$url=$v;break}}catch{}}}}catch{};" +
                    "$p.Id.ToString() + '@@@' + $p.ProcessName + '@@@' + $p.MainWindowTitle + '@@@' + $url}";
            Process p = PowerShellUtil.start(ps);
            String line;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) { line = r.readLine(); }
            p.waitFor();
            if (line == null) return null;
            String[] parts = line.split("@@@", 4);
            if (parts.length < 2) return null;
            long pid = Long.parseLong(parts[0].trim());
            String name = parts[1].trim();
            if (!name.toLowerCase(Locale.ROOT).endsWith(".exe")) name += ".exe";
            String title = parts.length >= 3 ? parts[2].trim() : "";
            String url = parts.length >= 4 ? parts[3].trim() : "";
            return new ProcessInfo(pid, name, title, url);
        } catch (Exception e) { return null; }
    }

    public boolean isAllowedBrowserPage(ProcessInfo info) {
        if (info == null) return false;
        String address = info.getBrowserUrl();
        if (address != null && !address.trim().isEmpty()) {
            return AppConfig.getInstance().isSiteAllowed(address.trim());
        }

        // A window title is not proof of the page's host: any page can put an
        // approved domain or brand fragment in its title.  Treat an unavailable
        // address bar as unverified so the DNS denial remains visible instead of
        // allowing a possible title-spoofed page through.
        return false;
    }
}
