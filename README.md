# CheatGuard

Java desktop app that locks down a student's PC during online exams — kills unauthorized
processes, restricts browser access to whitelisted sites, flags USB device insertions in
real time, and seals an undeletable audit log for every session.

## What ships

- **One installer, everything inside** — `dist\CheatGuard-Setup.exe` bundles the app AND
  its own trimmed Java runtime. Double-click → install → done. No JDK, no JAR, no
  separate setup step.
- **DNS-layer website allowlist** — an elevated helper points every adapter (IPv4 *and*
  IPv6) at a local filter; only admin-approved domains resolve. Browser DoH is forced
  off and re-blocked at the firewall. New adapters plugged in mid-exam are captured too.
- **Process watchdog** — when a session starts, every app that is already
  running is closed FIRST — including the ALLOWED ones, so no folder, file or
  tab opened before the exam survives inside them — and the invigilator reopens
  the needed apps from the monitor screen, which launches them ON the exam
  folder. Only then does monitoring and the alert counter begin. Windows shell
  components are never touched.
- **Allowed apps stay inside the exam folder** — their window titles are
  watched: an allowed app showing a file outside the exam folder is closed and
  logged as a red alert. The Windows recent-files lists (Start menu, jump
  lists, Open-dialog recents) are wiped at session start, so nothing pre-exam
  can be reopened in one click.
- **Readable log — three levels** — `OK` (grey) = routine enforcement such as an app
  closed at start; `WARN` (yellow) = a website the student tried to open but the block
  held; `ALERT` (red) = something actually got through: an unapproved folder, a USB
  device, an app that refused to close. The live header shows the running time, the
  ALERT count and the BLOCKED count separately.
- **Coding-test allowlist built in** — fresh installs (and older configs, once) start
  with the compilers, terminals, editors and contest judges a CP contest needs:
  gcc/g++/MinGW, make/cmake, Java, Python, Node, VS Code, Code::Blocks, cmd/PowerShell,
  and codeforces.com, atcoder.jp, codechef.com, leetcode.com, hackerrank.com, cses.fi,
  vjudge.net, toph.co and more. Admins can remove any of them per exam.
- **USB / external device monitor** — storage, network adapters and portable devices
  raise RED alerts the moment they appear.
- **Sealed audit logs** — AES-256 with a PBKDF2-derived key, SHA-256 signature, and
  ACL hardening (Administrators own, Users read-only) so Explorer cannot delete them.
  Deletion only from the dashboard, after the admin password + UAC.
- **No default password** — first run asks for one. PBKDF2-HMAC-SHA256 (210k rounds),
  machine-bound HMAC, 5-attempt escalating lockout, empty submissions cost nothing.
- **Clipboard hygiene** — pre-exam clipboard + Win+V history wiped at session start;
  fully usable during the session; untouched at the end.
- **Responsive UI** — every slow operation (UAC, sealing, log open/delete) runs on a
  worker thread; the window never freezes with "Not Responding".

## Build (one command)

```
build-installer.bat
```

Produces exactly one artifact: `dist\CheatGuard-Setup.exe` (app + bundled runtime).
Requires JDK 17+ and WiX Toolset 3.x on PATH (local copy is auto-detected from
`..\tools\wix`).

## Project layout

```
src\com\cheatguard\            application source
  config\                      paths + allowlist persistence
  core\                        session, log, violation model
  gui\                         Swing theme + screens (home, setup, monitor, settings, dashboard)
  security\                    credentials, vault (AES+signature), log protection
  watchdog\                    process scanner/controller, DNS server, network lockdown, devices
resources\network-lockdown.ps1 elevated helper (DNS redirect, DoH off, log ACLs)
test\CoreFlowTest.java         headless verification (credentials, vault, DNS, scanner)
build-installer.bat            single-command build → one installer exe
```

## Headless test

```
javac -encoding UTF-8 -d bin @sources.txt
javac -encoding UTF-8 -cp bin -d testbin test\CoreFlowTest.java
java -cp "bin;testbin" CoreFlowTest
```

All checks pass with an isolated data directory; nothing on the machine is modified.

## Security model

Red-teamed and hardened. The threat model is the signed-in student: a standard user
with full physical access, trying to cheat mid-exam or cover tracks afterwards.

Fixed by elevation + machine data: the app self-elevates at launch (UAC), and all
sensitive state lives under `C:\ProgramData\CheatGuard` —
- **stop.marker forgery closed** — the lockdown control directory is Administrators-only
  while a session runs, so the student cannot silently end the lockdown.
- **helper swap (admin RCE) closed** — the elevated PowerShell helper is staged where the
  student cannot rewrite it while the UAC prompt waits.
- **allowlist / credential tamper closed** — `whitelist.properties` and `admin.cred` are
  no longer inside the student's own profile.
- **taskkill immunity** — Windows UIPI blocks every medium-integrity process (Task
  Manager, cmd) from terminating or writing to the elevated app.
- **hidden-app watchdog** — new processes without a top-level window (tray apps,
  headless browsers) that start from student-writable locations are closed and logged.
- **DNS hardening** — DoT (853) firewalled off, plain 53 to known public resolvers
  blocked so custom tools cannot query around the filter, upstream replies validated
  (connected socket + ID + question check) against LAN spoofing, and the filter's own
  upstreams are kept outside the blocked list.
- **log integrity** — violation text is newline-sanitized so a crafted process name
  cannot forge audit lines; sealed logs stay AES+SHA-256 protected and ACL-hardened.
- **VPN / remote-control sweep** — tunnelling and remote-control clients (OpenVPN,
  WireGuard, Tailscale, Tor, TeamViewer, AnyDesk, VNC, RDP tools, and more) are closed
  wherever they are installed, because they reach the Internet without the DNS filter.
- **Tunnel-port firewall blocks** — during a session the elevated helper blocks the
  VPN/IPsec/WireGuard ports (UDP 500/4500/1194/51820), PPTP, outbound RDP, VNC and
  QUIC (HTTP/3), so even hand-rolled tunnelling tools have nowhere to connect.
- **Egress web lockdown** — the strongest layer: outbound web traffic is default-denied
  and only the addresses approved domains actually resolve to may connect (the local
  DNS filter feeds the firewall its allowlist live). This closes raw-IP HTTPS browsing.
  Before arming, the helper verifies an approved site really is reachable; on an
  exotic network it rolls itself back and the session continues in DNS-only mode
  (the log records which mode ran).
- **Fast user switching disabled** — the "Switch user" entry is hidden for the session
  (previous value restored at the end), and the log notes how many local accounts exist.

Known boundaries (stated honestly): an HTTPS proxy on a non-standard port or a tunnel
endpoint shared with an approved CDN IP cannot be told apart without deep packet
inspection; screen capture and a phone next to the keyboard are physical; an attacker
with the *local administrator password* can delete the credential store (the app
detects tampering and forces a visible reset, but a local admin is above client-side
enforcement); and a cheat file kept entirely inside an app that never shows a path in
its title bar (for example a note typed into an editor with no file name) is invisible
to title monitoring — the fresh-start rule, the recent-list wipe and the folder
monitor close the practical routes, but they cannot read a program's mind.

Round-2 hardening (2.2):
- **Proxy/PAC lockdown** — any user-configured HTTP proxy or PAC URL force-disables
  during a session (snapshot restored at the end); a proxy would resolve names on its
  own and skip the DNS filter entirely.
- **IPv6 leak guard** — if real IPv6 resolvers are configured but `::1` could not be
  bound, the session refuses to start instead of silently filtering IPv4 only.
- **Background-watchdog precision** — process identity uses PID + start instant (PID
  reuse is judged correctly), unattributable processes are re-checked instead of
  whitelisted, and the student-writable test is inverted: anything outside the Windows
  directory, Program Files and ProgramData counts as student space (second drives too).
- **Dashboard password field clears** after every open/delete, so a pre-filled admin
  password is never left on screen.
- PowerShell probes run window-hidden (no console flashes at session start), and the
  setup screen warns loudly before starting a session with no approved websites.

## Quick start for a team

1. Copy `CheatGuard-Setup.exe` to the exam machine and double-click it (admin rights).
2. First launch: set the administrator password. Then open **Allowed apps and
   websites** and add the exam platform (e.g. `codeforces.com`) and any IDEs.
3. **Start exam session** — enter course + student ID, approve the administrator
   prompt, hand the laptop to the student.
4. **End session and seal log** — the log is sealed, protected, and readable later
   from **Session dashboard**.

Installed support tools (in the app folder, e.g. `C:\Program Files\CheatGuard`):

- **emergency-restore.bat** — repairs DNS/firewall after an abnormal ending
  (power loss, crash). Refuses to run while a session is actually active.
- **diagnostics.bat** — collects network/DNS state and the recent app log into
  `Desktop\CheatGuard-Diagnostics.txt` to send to the team.

Diagnostics log: `C:\ProgramData\CheatGuard\logs\cheatguard-<date>.log`.

## Admin workflows

- **Allowed apps and websites** — allowlists for the watchdog and DNS filter.
- **Session dashboard** — open/delete sealed logs (admin password; delete also asks UAC).
- **Emergency network restore** — the installer config includes the elevated helper;
  a stale session is auto-recovered on next launch, or run the helper from
  `%LOCALAPPDATA%\CheatGuard\network` as administrator.
