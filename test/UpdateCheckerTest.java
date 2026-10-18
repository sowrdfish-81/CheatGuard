package com.cheatguard.config;

/** Regression tests for release asset selection and URL validation. */
public class UpdateCheckerTest {
    public static void main(String[] args) {
        String json = "{\"assets\":["
                + "{\"name\":\"notes.txt\",\"browser_download_url\":\"https://github.com/sowrdfish-81/CheatGuard/releases/download/v4/notes.txt\"},"
                + "{\"name\":\"CheatGuard-Setup.exe\",\"browser_download_url\":\"https://github.com/sowrdfish-81/CheatGuard/releases/download/v4/CheatGuard-Setup.exe\"}]}";
        String expected = "https://github.com/sowrdfish-81/CheatGuard/releases/download/v4/CheatGuard-Setup.exe";
        if (!expected.equals(UpdateChecker.findInstallerDownloadUrl(json))) {
            throw new AssertionError("installer URL was not bound to the matching asset");
        }
        if (UpdateChecker.isTrustedDownloadUrl("http://github.com/example.exe")) {
            throw new AssertionError("plain HTTP update URL accepted");
        }
        if (UpdateChecker.isTrustedDownloadUrl("https://evil.example/example.exe")) {
            throw new AssertionError("untrusted update host accepted");
        }
        System.out.println("UpdateCheckerTest: PASS");
    }
}
