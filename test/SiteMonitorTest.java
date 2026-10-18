import com.cheatguard.config.AppConfig;
import com.cheatguard.watchdog.ProcessInfo;
import com.cheatguard.watchdog.SiteMonitor;

/** Regression test for conservative browser title fallback. */
public class SiteMonitorTest {
    public static void main(String[] args) {
        AppConfig.getInstance().addAllowedSite("exam.com");
        SiteMonitor monitor = new SiteMonitor();
        expect("spoofed title is not trusted",
                !monitor.isAllowedBrowserPage(new ProcessInfo(1, "chrome.exe", "example.com - Chrome")));
        expect("missing URL is not trusted even for an approved-looking title",
                !monitor.isAllowedBrowserPage(new ProcessInfo(1, "chrome.exe", "exam.com - Chrome")));
        expect("verified approved URL is allowed",
                monitor.isAllowedBrowserPage(new ProcessInfo(1, "chrome.exe", "anything",
                        "https://portal.exam.com/start")));
        System.out.println("SiteMonitorTest: PASS");
    }

    private static void expect(String name, boolean condition) {
        if (!condition) throw new AssertionError(name);
    }
}
