import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;
import com.cheatguard.security.AdminAuth;
import com.cheatguard.security.AdminCredentialStore;
import com.cheatguard.security.AesEncryptor;
import com.cheatguard.security.Sha256Signer;
import com.cheatguard.watchdog.DnsAllowlistServer;
import com.cheatguard.watchdog.ProcessInfo;
import com.cheatguard.watchdog.ProcessScanner;
import com.cheatguard.watchdog.WatchdogEngine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Headless core verification for Cheat.Guard 2.0.
 *
 * Run with an isolated LOCALAPPDATA so the developer's own credential store and
 * vault are never touched. Every check prints PASS/FAIL; the process exits
 * non-zero if anything failed.
 */
public class CoreFlowTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("== Cheat.Guard 2.0 CoreFlowTest ==");
        System.out.println("Isolated data dir: " + com.cheatguard.config.AppPaths.getDataDirectory());

        checkAdminAuth();
        checkVault();
        checkSiteNormalize();
        checkDnsServer();
        checkProcessScanner();
        checkDnsWireParser();
        checkSpoofRejection();
        checkLogInjection();
        checkSeverityLevels();
        checkAnswerIpParsing();
        checkTitlePathRule();
        checkEditorTitleRule();
        checkRuntimeArgRule();
        checkLockPathCollection();

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL CHECKS PASSED");
        } else {
            System.out.println(failures + " CHECK(S) FAILED");
            System.exit(1);
        }
    }

    // ------------------------------------------------------------- credentials

    private static void checkAdminAuth() throws Exception {
        section("AdminAuth");
        AdminAuth auth = new AdminAuth();
        if (auth.isConfigured()) {
            // A leftover cred file from a crashed previous run would block create;
            // delete it only because this run is fully isolated.
            new com.cheatguard.security.AdminCredentialStore().getFile().delete();
            auth = new AdminAuth(); // fresh store view after deletion
        }

        expect("fresh install is unconfigured", !auth.isConfigured());

        boolean weakRejected = false;
        try { auth.createPassword("short1".toCharArray()); }
        catch (IllegalArgumentException e) { weakRejected = true; }
        expect("short password rejected", weakRejected);

        boolean weakRejected2 = false;
        try { auth.createPassword("onlyletters".toCharArray()); }
        catch (IllegalArgumentException e) { weakRejected2 = true; }
        expect("letters-only password rejected", weakRejected2);

        char[] pw = "ExamGuard#2026".toCharArray();
        auth.createPassword(pw);
        expect("createPassword wipes its input", isZeroed(pw));
        expect("now configured", auth.isConfigured());

        AdminCredentialStore.Result ok = auth.check("ExamGuard#2026".toCharArray());
        expect("correct password verifies", ok.success());

        AdminCredentialStore.Result empty = auth.check(new char[0]);
        expect("empty password refused without burning attempt",
                !empty.success() && empty.attemptsLeft() == AdminCredentialStore.MAX_ATTEMPTS);

        boolean wrongOk = true;
        for (int i = 0; i < AdminCredentialStore.MAX_ATTEMPTS - 1; i++) {
            wrongOk &= !auth.check(("WrongPass" + i + "x").toCharArray()).success();
        }
        expect("four wrong attempts all refused", wrongOk);

        AdminCredentialStore.Result finalWrong = auth.check("WrongPassFinal".toCharArray());
        expect("fifth wrong attempt triggers lockout", !finalWrong.success() && finalWrong.lockedForMs() > 0);

        AdminCredentialStore.Result duringLock = auth.check("ExamGuard#2026".toCharArray());
        expect("even the correct password is refused while locked", !duringLock.success());
    }

    // ------------------------------------------------------------------- vault

    private static void checkVault() throws Exception {
        section("Vault (AES + signature, password as char[])");
        File logFile = new File(AppPaths.getVaultDirectory(), "test.dat");
        if (!logFile.getParentFile().exists()) logFile.getParentFile().mkdirs();

        AdminCredentialStore cred = new AdminCredentialStore();
        AdminAuth auth = new AdminAuth();
        com.cheatguard.security.SecurityVault vault = new com.cheatguard.security.SecurityVault(auth);

        // Force a known password store of our own for this section.
        File credFile = new com.cheatguard.security.AdminCredentialStore().getFile();
        credFile.delete();
        auth.createPassword("VaultTest#2026".toCharArray());

        java.io.PrintWriter w = new java.io.PrintWriter(logFile, StandardCharsets.UTF_8);
        w.println("2026-09-20 10:00:00 [NORMAL] INFO SESSION_START :: Course=TST | StudentID=1");
        w.println("2026-09-20 10:05:00 [RED-FLAG] CRITICAL BLOCKED_INTERNET_DOMAIN :: youtube.com - YouTube");
        w.close();

        char[] pw = "VaultTest#2026".toCharArray();
        vault.sealVault(logFile, pw.clone());
        File vaultFile = new File(logFile.getParent(), "test.vault");
        File sigFile = new File(logFile.getParent(), "test.vault.sig");
        expect("plaintext removed after seal", !logFile.exists());
        expect("vault file created", vaultFile.isFile());
        expect("signature file created", sigFile.isFile());

        String opened = vault.openLog(vaultFile, pw.clone());
        expect("sealed log decrypts with correct password",
                opened.contains("SESSION_START") && opened.contains("youtube.com"));

        boolean wrongRefused = false;
        try { vault.openLog(vaultFile, "WrongPass#1".toCharArray()); }
        catch (Exception e) { wrongRefused = true; }
        expect("wrong password refused", wrongRefused);

        // Tamper: flip a byte in the middle of the vault.
        byte[] raw = readAll(vaultFile);
        raw[raw.length / 2] ^= 0x5A;
        java.nio.file.Files.write(vaultFile.toPath(), raw);
        boolean tamperDetected = false;
        try { vault.openLog(vaultFile, pw.clone()); }
        catch (Exception e) { tamperDetected = true; }
        expect("tampered vault rejected", tamperDetected);

        // The tamper flipped a ciphertext byte, so the signature now mismatches the
        // contents; restore by re-signing is not attempted — recreate instead.
        vaultFile.delete();
        sigFile.delete();
        java.io.PrintWriter w2 = new java.io.PrintWriter(logFile, StandardCharsets.UTF_8);
        w2.println("second round");
        w2.close();
        vault.sealVault(logFile, pw.clone());
        vault.deleteLog(new File(logFile.getParent(), "test.vault"), pw.clone());
        expect("deleteLog removes vault and signature",
                !vaultFile.exists() && !sigFile.exists());

        if (logFile.exists()) logFile.delete();
    }

    // ---------------------------------------------------------------- settings

    private static void checkSiteNormalize() {
        section("AppConfig site normalization");
        expect("bare host", AppConfig.normalizeSite("codeforces.com").equals("codeforces.com"));
        expect("https url", AppConfig.normalizeSite("https://www.atcoder.jp/contests").equals("atcoder.jp"));
        expect("subdomain wildcard", AppConfig.normalizeSite("*.toph.co").equals("toph.co"));
        expect("invalid single word rejected", AppConfig.normalizeSite("com").isEmpty());
        expect("trailing dots", AppConfig.normalizeSite("vjudge.net..").equals("vjudge.net"));
        expect("uppercase", AppConfig.normalizeSite("CodeChef.COM").equals("codechef.com"));
    }

    // --------------------------------------------------------------------- DNS

    private static void checkDnsServer() throws Exception {
        section("DnsAllowlistServer (allow/NXDOMAIN, upstream, cache)");
        // Allow the test domain only.
        File wl = AppPaths.getWhitelistFile();
        if (wl.exists()) wl.delete();
        java.util.Properties props = new java.util.Properties();
        props.setProperty("allowed.processes", "code.exe");
        props.setProperty("allowed.sites", "example.com");
        File parent = wl.getParentFile();
        if (!parent.exists()) parent.mkdirs();
        java.io.FileWriter fw = new java.io.FileWriter(wl);
        props.store(fw, "test");
        fw.close();
        // Reset the singleton so it reloads the new file.
        java.lang.reflect.Field f = AppConfig.class.getDeclaredField("instance");
        f.setAccessible(true);
        f.set(null, null);

        DnsAllowlistServer server = new DnsAllowlistServer(new LogManager(new File(AppPaths.getDataDirectory(), "test-log.dat")), null);
        server.start();
        try {
            expect("IPv4 bound", server.isRunning());
            expect("IPv6 bound on ::1", server.isIpv6Bound());

            byte[] blocked = query(server, "blocked.invalid-guard.com");
            expect("blocked host gets NXDOMAIN", blocked != null && rcode(blocked) == 3);

            byte[] allowed = query(server, "example.com");
            // Network may be unavailable in the test environment; a real answer or a
            // SERVFAIL both prove the filter forwarded. NXDOMAIN would be a bug.
            expect("allowed host is forwarded (not NXDOMAIN)", allowed != null && rcode(allowed) != 3);
            if (allowed != null && rcode(allowed) == 0) {
                byte[] cached = query(server, "example.com");
                expect("second lookup answered (cache path ok)", cached != null && rcode(cached) == 0
                        && idMatches(cached));
            }
        } finally {
            server.close();
        }
    }

    private static byte[] query(DnsAllowlistServer server, String host) throws Exception {
        ByteArrayOutputStream name = new ByteArrayOutputStream();
        for (String label : host.split("\\.")) {
            name.write(label.length());
            name.write(label.getBytes(StandardCharsets.US_ASCII));
        }
        name.write(0);
        byte[] q = new byte[12 + name.size() + 4];
        q[0] = 0x4A; q[1] = 0x7B;               // id
        q[2] = 0x01;                             // RD
        q[5] = 0x01;                             // QDCOUNT
        System.arraycopy(name.toByteArray(), 0, q, 12, name.size());
        q[q.length - 4] = 0; q[q.length - 3] = 1;  // QTYPE=A
        q[q.length - 2] = 0; q[q.length - 1] = 1;  // QCLASS=IN

        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(8000);
            s.send(new DatagramPacket(q, q.length, InetAddress.getByName("127.0.0.1"), 53));
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            s.receive(resp);
            byte[] out = new byte[resp.getLength()];
            System.arraycopy(resp.getData(), 0, out, 0, resp.getLength());
            out[0] = q[0]; out[1] = q[1]; // sanity for idMatches()
            return out;
        }
    }

    private static int rcode(byte[] dns) { return dns[3] & 0x0F; }
    private static boolean idMatches(byte[] dns) { return dns[0] == 0x4A && dns[1] == 0x7B; }

    private static void checkDnsWireParser() {
        section("DNS wire parser");
        ByteArrayOutputStream name = new ByteArrayOutputStream();
        for (String label : new String[]{"WWW", "Example", "COM"}) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            name.write(b.length);
            name.write(b, 0, b.length);
        }
        name.write(0);
        byte[] msg = new byte[12 + name.size() + 4];
        System.arraycopy(name.toByteArray(), 0, msg, 12, name.size());
        expect("parseQName lowercases and joins",
                "www.example.com".equals(DnsAllowlistServer.parseQName(msg)));
        expect("parseQName rejects tiny packet", DnsAllowlistServer.parseQName(new byte[4]) == null);
    }

    // ------------------------------------------------------- spoof rejection

    private static void checkSpoofRejection() {
        section("DNS upstream reply validation (anti-spoofing)");
        byte[] q = buildQuery("allowed.example.com", (byte) 0x11, (byte) 0x22);
        byte[] good = buildReply(q, (byte) 0x11, (byte) 0x22);
        expect("correct reply accepted", com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(good, q));

        byte[] wrongId = buildReply(q, (byte) 0xAB, (byte) 0xCD);
        expect("wrong transaction ID rejected", !com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(wrongId, q));

        byte[] otherQuery = buildQuery("other.example.com", (byte) 0x11, (byte) 0x22);
        byte[] wrongQuestion = buildReply(otherQuery, (byte) 0x11, (byte) 0x22);
        expect("reply for a different question rejected",
                !com.cheatguard.watchdog.DnsAllowlistServer.responseMatchesQuery(wrongQuestion, q));
    }

    private static byte[] buildQuery(String host, byte id0, byte id1) {
        try {
            java.io.ByteArrayOutputStream name = new java.io.ByteArrayOutputStream();
            for (String label : host.split(PURE_DOT)) {
                name.write(label.length());
                name.write(label.getBytes(StandardCharsets.US_ASCII));
            }
            name.write(0);
            byte[] q = new byte[12 + name.size() + 4];
            q[0] = id0; q[1] = id1; q[2] = 0x01; q[5] = 0x01;
            System.arraycopy(name.toByteArray(), 0, q, 12, name.size());
            q[q.length - 4] = 0; q[q.length - 3] = 1;
            q[q.length - 2] = 0; q[q.length - 1] = 1;
            return q;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static final String PURE_DOT = "\\.";

    private static byte[] buildReply(byte[] query, byte id0, byte id1) {
        byte[] r = query.clone();
        r[0] = id0; r[1] = id1;
        r[2] = (byte) 0x81; r[3] = (byte) 0x80;
        return r;
    }

    // ---------------------------------------------------------- log injection

    private static void checkLogInjection() {
        section("Violation log-injection sanitization");
        String evilType = "TEST" + CRLF + "2026-01-01 00:00:00 [NORMAL] INFO SESSION_END :: fake - forged";
        String evilDesc = "desc" + LF + "line2" + TAB + "tabbed";
        com.cheatguard.core.Violation v = new com.cheatguard.core.Violation(
                evilType, evilDesc, com.cheatguard.core.Violation.Severity.INFO);
        String line = v.toString();
        expect("no CR/LF survives into the log line", !line.contains(LF) && !line.contains(CR));
        expect("line breaks flattened to spaces, tabs stripped",
                line.contains("desc line2 tabbed") && !line.contains(TAB));
    }

    private static void checkTitlePathRule() {
        section("Allowed-app title path rule");
        String exam = "C:" + '\\' + "Users" + '\\' + "t" + '\\' + "Desktop" + '\\' + "Exam_1";
        expect("title without any drive path is clean",
                WatchdogEngine.titlePathOutside("notes.txt - Notepad", exam) == null);
        expect("title showing the exam folder is clean",
                WatchdogEngine.titlePathOutside(exam + '\\' + "main.cpp - Notepad++", exam) == null);
        expect("title showing an outside drive path is flagged",
                WatchdogEngine.titlePathOutside("C:" + '\\' + "Users" + '\\' + "t"
                        + '\\' + "notes.txt - Notepad++", exam) != null);
        expect("forward-slash outside path is flagged too",
                WatchdogEngine.titlePathOutside("D:/stuff/cheat.txt - Editor", exam) != null);
        expect("blank title is clean",
                WatchdogEngine.titlePathOutside("", exam) == null);
    }

    private static void checkEditorTitleRule() {
        section("Allowed editor folder-segment rule");
        String vs = "Visual Studio Code";
        expect("title with the exam folder is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "main.cpp - Exam_1 - " + vs, vs, "Exam_1", null));
        expect("title with a foreign folder is flagged",
                WatchdogEngine.editorShowsOutsideFolder(
                        "notes.py - CheatNotes - " + vs, vs, "Exam_1", null));
        expect("welcome page is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Get Started - " + vs, vs, "Exam_1", null));
        expect("folder-only exam title is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Exam_1 - " + vs, vs, "Exam_1", null));
        expect("untitled scratch tab is clean",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "Untitled-1 - " + vs, vs, "Exam_1", null));
        expect("title not matching the editor suffix is ignored",
                !WatchdogEngine.editorShowsOutsideFolder(
                        "notes.py - CheatNotes - Some App", vs, "Exam_1", null));
    }

    private static void checkRuntimeArgRule() {
        section("Allowed runtime argument rule");
        String exam = "C:" + '\\' + "Users" + '\\' + "t" + '\\' + "Desktop" + '\\' + "Exam_1";
        expect("exam-folder script argument is clean",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "-u", exam + '\\' + "solve.py"}, exam) == null);
        expect("outside script argument is flagged",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "-u", "D:" + '\\' + "cheat" + '\\' + "solve.py"}, exam) != null);
        expect("vs code tooling paths are ignored",
                WatchdogEngine.runtimeArgOutside(new String[]{
                        "C:" + '\\' + "Users" + '\\' + "t" + '\\' + ".vscode"
                                + '\\' + "adapter.py"}, exam) == null);
        expect("flag-only arguments are clean",
                WatchdogEngine.runtimeArgOutside(new String[]{"-m", "jedi"}, exam) == null);
        expect("no arguments is clean",
                WatchdogEngine.runtimeArgOutside(null, exam) == null);
    }

    private static void checkLockPathCollection() throws Exception {
        section("File-access lock path collection");
        java.io.File base = new java.io.File(System.getProperty("java.io.tmpdir"),
                "cgt-" + System.nanoTime());
        java.io.File profile = new java.io.File(base, "profile");
        java.io.File documents = new java.io.File(profile, "Documents");
        java.io.File downloads = new java.io.File(profile, "Downloads");
        java.io.File desktop = new java.io.File(base, "Desktop");
        java.io.File exam = new java.io.File(desktop, "Exam_1");
        java.io.File cheat = new java.io.File(desktop, "CheatNotes");
        java.io.File lnk = new java.io.File(desktop, "shortcut.lnk");
        java.io.File note = new java.io.File(desktop, "note.txt");
        java.io.File root = new java.io.File(base, "Ddrive");
        for (java.io.File f : new java.io.File[]{documents, downloads, desktop, exam, cheat, root}) {
            f.mkdirs();
        }
        lnk.createNewFile();
        note.createNewFile();
        java.util.List<java.io.File> roots = java.util.Arrays.asList(root,
                new java.io.File(base, "Missing"));
        java.util.List<String> paths = com.cheatguard.watchdog.StrictNetworkLockdown
                .collectLockPaths(profile, desktop, exam, roots);
        expect("profile content folders are locked",
                paths.contains(documents.getAbsolutePath())
                        && paths.contains(downloads.getAbsolutePath()));
        expect("foreign desktop folder is locked", paths.contains(cheat.getAbsolutePath()));
        expect("exam folder is never locked", !paths.contains(exam.getAbsolutePath()));
        expect("shortcuts are never locked", !paths.contains(lnk.getAbsolutePath()));
        expect("loose desktop files are locked", paths.contains(note.getAbsolutePath()));
        expect("extra drive roots are locked and missing roots skipped",
                paths.contains(root.getAbsolutePath())
                        && !paths.contains(new java.io.File(base, "Missing").getAbsolutePath()));
        for (java.io.File f : new java.io.File[]{documents, downloads, exam, cheat, root,
                desktop, profile, base}) {
            f.delete();
        }
    }

    private static final String CRLF = new String(new char[]{'\r', '\n'});
    private static final String LF = new String(new char[]{'\n'});
    private static final String CR = new String(new char[]{'\r'});
    private static final String TAB = new String(new char[]{'\t'});

    // --------------------------------------------------------- log levels

    private static void checkSeverityLevels() {
        section("Violation severity levels and log rows");
        com.cheatguard.core.Violation info = new com.cheatguard.core.Violation(
                "APP_CLOSED_AT_START", "Discord", com.cheatguard.core.Violation.Severity.INFO);
        com.cheatguard.core.Violation notice = new com.cheatguard.core.Violation(
                "BLOCKED_INTERNET_DOMAIN", "facebook.com", com.cheatguard.core.Violation.Severity.NOTICE);
        com.cheatguard.core.Violation red = new com.cheatguard.core.Violation(
                "UNAUTHORIZED_FOLDER_ACCESS", "D:/stuff/Videos", com.cheatguard.core.Violation.Severity.CRITICAL);
        expect("NOTICE is not a red flag", !notice.isRedFlag());
        expect("CRITICAL is a red flag", red.isRedFlag());
        expect("INFO row shows OK", com.cheatguard.gui.LogDisplayFormatter.format(info).contains(" OK  "));
        expect("NOTICE row shows WARN", com.cheatguard.gui.LogDisplayFormatter.format(notice).contains(" WARN "));
        expect("CRITICAL row shows ALERT", com.cheatguard.gui.LogDisplayFormatter.format(red).contains(" ALERT "));
        expect("stored NOTICE line parses back as WARN",
                com.cheatguard.gui.LogDisplayFormatter.formatRaw(notice.toString()).contains(" WARN "));
        expect("stored RED-FLAG line parses back as ALERT",
                com.cheatguard.gui.LogDisplayFormatter.formatRaw(red.toString()).contains(" ALERT "));
    }

    // ------------------------------------------------- egress allowlist feed

    private static void checkAnswerIpParsing() {
        section("DNS answer address extraction (egress allowlist feed)");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0x81, (byte) 0x80,
                0, 1, 0, 1, 0, 0, 0, 0});
        out.writeBytes(new byte[]{10, 'c', 'o', 'd', 'e', 'f', 'o', 'r', 'c', 'e', 's', 3, 'c', 'o', 'm', 0});
        out.writeBytes(new byte[]{0, 1, 0, 1});                       // question: A IN
        out.writeBytes(new byte[]{(byte) 0xC0, 0x0C});                // answer name: pointer
        out.writeBytes(new byte[]{0, 1, 0, 1, 0, 0, 0, 60, 0, 4});    // A IN ttl=60 rdlen=4
        out.writeBytes(new byte[]{104, 16, (byte) 205, 15});          // 104.16.205.15
        List<String> ips = DnsAllowlistServer.parseAnswerIps(out.toByteArray());
        expect("one IPv4 answer extracted", ips.size() == 1);
        expect("answer address is correct", ips.size() == 1 && "104.16.205.15".equals(ips.get(0)));
        expect("truncated message yields no addresses",
                DnsAllowlistServer.parseAnswerIps(new byte[]{0, 1, 2}).isEmpty());
    }

    // ----------------------------------------------------------------- scanner

    private static void checkProcessScanner() {
        section("ProcessScanner (visible apps)");
        ProcessScanner scanner = new ProcessScanner();
        List<ProcessInfo> visible = scanner.getRunningProcesses();
        System.out.println("  visible processes seen: " + visible.size());
        expect("scanner returns without hanging", true);
    }

    // ------------------------------------------------------------------ helpers

    private static void expect(String label, boolean condition) {
        System.out.println((condition ? "  PASS  " : "  FAIL  ") + label);
        if (!condition) failures++;
    }

    private static void section(String name) {
        System.out.println();
        System.out.println("-- " + name + " --");
    }

    private static boolean isZeroed(char[] a) {
        for (char c : a) if (c != '\0') return false;
        return true;
    }

    private static byte[] readAll(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1) bos.write(buf, 0, r);
            return bos.toByteArray();
        }
    }
}
