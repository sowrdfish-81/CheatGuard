package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local DNS allowlist resolver — the enforcement point for website lockdown.
 *
 * <p>The elevated helper points every adapter's DNS at this server, so the whole
 * machine resolves through it. A query is answered only when its hostname passes
 * {@link AppConfig#isSiteAllowed(String)}; everything else gets NXDOMAIN, so an
 * unapproved domain cannot be resolved by any program — not just by a browser.
 *
 * <p>Enforcing at name resolution keeps approved sites working normally: an
 * approved lookup is resolved and the browser connects to the real site directly,
 * with no proxy in the path that could fail or be ignored.
 *
 * <p>Approved lookups are resolved through the resolvers the computer was already
 * using before the session (campus DNS usually answers faster and never blocks
 * internal hosts), falling back to public resolvers when none could be captured.
 * Successful answers are cached for a few seconds so a page fan-out of a dozen
 * names costs one upstream round-trip, not a dozen.
 *
 * <p>Windows places no privilege restriction on low ports, so binding UDP 53
 * works from the normal (non-elevated) application process.
 */
public final class DnsAllowlistServer implements Closeable {

    /** Standard DNS port; adapters are redirected here on 127.0.0.1. */
    public static final int DNS_PORT = 53;

    private static final int MAX_PACKET = 4096;
    private static final int UPSTREAM_TIMEOUT_MS = 3000;
    private static final int MAX_LOGGED_HOSTS = 400;
    /**
     * Settling window right after the lockdown starts: the machine's own cleanup is
     * still running (tray apps, chat clients and update services are being closed)
     * and their dying lookups are the app's noise, not student activity. Blocked
     * lookups inside this window are dropped instead of being reported.
     */
    private static final long STARTUP_GRACE_MS = 60_000L;
    /** Successful approved answers are replayed for this long before re-querying. */
    private static final long CACHE_TTL_MS = 30_000L;
    private static final int CACHE_MAX_ENTRIES = 512;

    /**
     * Fallback resolvers used only when no system resolver could be captured.
     * Deliberately OUTSIDE the firewall's public-resolver block list (which stops a
     * student querying 8.8.8.8/1.1.1.1 directly from a custom tool): the filter's
     * own upstream traffic must keep working on networks where the captured system
     * resolvers are unreachable.
     */
    private static final List<String> DEFAULT_UPSTREAMS = List.of("9.9.9.10", "149.112.112.10");

    /**
     * Public resolvers the exam firewall blocks on port 53. Any system resolver
     * found in this list is dropped from the captured upstreams so the filter never
     * blocks its own path.
     */
    static final java.util.Set<String> BLOCKED_PUBLIC_RESOLVERS = java.util.Set.of(
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15");

    private final LogManager logManager;
    private final ViolationListener listener;
    private final WebsiteViolationReporter reporter = new WebsiteViolationReporter();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Set<String> loggedBlockedHosts =
            Collections.synchronizedSet(new LinkedHashSet<>());
    private final long graceUntil = System.currentTimeMillis() + STARTUP_GRACE_MS;
    /** Every address an approved domain has resolved to this session (egress allowlist). */
    private final Set<String> allowedAnswerIps = Collections.synchronizedSet(new LinkedHashSet<>());
    /** Optional file the elevated helper polls to keep its firewall allowlist current. */
    private final File allowedIpSink;
    private final List<String> upstreams;
    private final ConcurrentHashMap<String, CachedAnswer> answerCache = new ConcurrentHashMap<>();
    private ScheduledExecutorService ipFlusher;
    private volatile boolean ipListDirty;

    private volatile DatagramSocket socket;
    private volatile DatagramSocket socketV6;
    private final List<Thread> acceptThreads = new ArrayList<>();
    private ExecutorService workers;

    public DnsAllowlistServer(LogManager logManager, ViolationListener listener) {
        this(logManager, listener, DEFAULT_UPSTREAMS, null);
    }

    public DnsAllowlistServer(LogManager logManager, ViolationListener listener,
                              List<String> systemUpstreams) {
        this(logManager, listener, systemUpstreams, null);
    }

    /**
     * @param systemUpstreams the machine's original resolvers, captured before the
     *                        adapters were redirected; empty list falls back to the
     *                        public resolvers
     * @param allowedIpSink   when non-null, the addresses answered for approved
     *                        domains are written here (one per line) a few times a
     *                        minute so the elevated egress firewall can follow
     */
    public DnsAllowlistServer(LogManager logManager, ViolationListener listener,
                              List<String> systemUpstreams, File allowedIpSink) {
        this.logManager = logManager;
        this.listener = listener;
        this.allowedIpSink = allowedIpSink;
        List<String> cleaned = new ArrayList<>();
        if (systemUpstreams != null) {
            for (String s : systemUpstreams) {
                if (s == null || !s.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
                if (BLOCKED_PUBLIC_RESOLVERS.contains(s)) continue;       // blocked on 53 for everyone
                if (s.startsWith("45.90.28.") || s.startsWith("45.90.30.")) continue;
                if (s.startsWith("127.") || s.equals("0.0.0.0")) continue;
                if (!cleaned.contains(s)) cleaned.add(s);
                if (cleaned.size() >= 4) break;
            }
        }
        for (String fallback : DEFAULT_UPSTREAMS) {
            if (cleaned.size() >= 4) break;
            if (!cleaned.contains(fallback)) cleaned.add(fallback);
        }
        this.upstreams = List.copyOf(cleaned);
    }

    /** A successful upstream answer with the query ID blanked for reuse. */
    private record CachedAnswer(byte[] response, long expiresAt) {
    }

    /**
     * Bind the loopback DNS port for both address families and begin serving.
     *
     * <p>IPv4 (127.0.0.1) is required. IPv6 (::1) is bound as well when available:
     * Windows keeps separate IPv6 DNS servers per adapter and prefers them, so
     * leaving that family unfiltered would either leak lookups or — once outbound
     * port 53 is denied to other programs — stall resolution for approved sites
     * while Windows waits for the unreachable IPv6 servers.
     *
     * @throws IOException if 127.0.0.1:53 is already taken (another DNS or Internet
     *                     Connection Sharing service); the caller must surface this
     *                     because the allowlist would otherwise not be enforced.
     */
    public void start() throws IOException {
        if (running.get()) return;
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), DNS_PORT));
        socket.setSoTimeout(1000);
        try {
            socketV6 = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"), DNS_PORT));
            socketV6.setSoTimeout(1000);
        } catch (Exception ipv6Unavailable) {
            socketV6 = null;
        }
        running.set(true);
        workers = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "CheatGuard-DNS-Worker");
            t.setDaemon(true);
            return t;
        });
        startAcceptThread(socket, "CheatGuard-DNS");
        if (socketV6 != null) startAcceptThread(socketV6, "CheatGuard-DNS-v6");
        if (allowedIpSink != null) {
            ipFlusher = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "CheatGuard-IpSink");
                t.setDaemon(true);
                return t;
            });
            ipFlusher.scheduleWithFixedDelay(this::flushAllowedIps, 3, 3, TimeUnit.SECONDS);
        }
    }

    /** True when ::1:53 is also being served, so IPv6 DNS can be redirected too. */
    public boolean isIpv6Bound() {
        return socketV6 != null;
    }

    private void startAcceptThread(DatagramSocket bound, String name) {
        Thread t = new Thread(() -> acceptLoop(bound), name);
        t.setDaemon(true);
        acceptThreads.add(t);
        t.start();
    }

    public boolean isRunning() {
        return running.get();
    }

    @Override
    public void close() {
        running.set(false);
        DatagramSocket s = socket;
        if (s != null) s.close();
        socket = null;
        DatagramSocket s6 = socketV6;
        if (s6 != null) s6.close();
        socketV6 = null;
        if (workers != null) {
            workers.shutdownNow();
            try {
                workers.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            workers = null;
        }
        for (Thread t : acceptThreads) t.interrupt();
        acceptThreads.clear();
        if (ipFlusher != null) {
            ipFlusher.shutdown();
            flushAllowedIps(); // leave the helper the last known list
            ipFlusher = null;
        }
        loggedBlockedHosts.clear();
        answerCache.clear();
    }

    private void acceptLoop(DatagramSocket bound) {
        while (running.get()) {
            byte[] buf = new byte[MAX_PACKET];
            DatagramPacket request = new DatagramPacket(buf, buf.length);
            try {
                bound.receive(request);
                ExecutorService pool = workers;
                if (pool != null) pool.submit(() -> handle(request, bound));
            } catch (SocketTimeoutException ignored) {
                // periodic wake-up so the running flag is re-checked
            } catch (Exception e) {
                if (running.get() && !bound.isClosed()) {
                    // transient receive failure; keep serving
                    continue;
                }
                return;
            }
        }
    }

    private void handle(DatagramPacket request, DatagramSocket bound) {
        byte[] query = new byte[request.getLength()];
        System.arraycopy(request.getData(), request.getOffset(), query, 0, request.getLength());

        String host = parseQName(query);
        boolean allowed = host != null && AppConfig.getInstance().isSiteAllowed(host);

        byte[] response;
        if (allowed) {
            response = resolveApproved(query, host);
        } else {
            response = buildResponse(query, RCODE_NXDOMAIN);
            if (host != null) recordBlocked(host);
        }

        if (response == null) return;
        try {
            if (!bound.isClosed()) {
                bound.send(new DatagramPacket(response, response.length,
                        request.getAddress(), request.getPort()));
            }
        } catch (IOException ignored) {
            // client went away
        }
    }

    /**
     * Answer an approved lookup: replay a recent identical answer when one is
     * cached, otherwise forward upstream. Caching collapses a browser's burst of
     * repeated lookups (page + assets + safe-browsing refreshes) into a single
     * upstream round-trip and makes approved pages load noticeably faster.
     */
    private byte[] resolveApproved(byte[] query, String host) {
        String key = cacheKey(query, host);
        if (key != null) {
            CachedAnswer cached = answerCache.get(key);
            if (cached != null && cached.expiresAt() > System.currentTimeMillis()) {
                collectIps(parseAnswerIps(cached.response()));
                return withQueryId(cached.response(), query);
            }
            if (cached != null) answerCache.remove(key);
        }

        byte[] response = forward(query);
        if (response != null && key != null && answerCount(response) > 0) {
            collectIps(parseAnswerIps(response));
            if (answerCache.size() >= CACHE_MAX_ENTRIES) answerCache.clear();
            answerCache.put(key, new CachedAnswer(withQueryId(response, new byte[]{0, 0}),
                    System.currentTimeMillis() + CACHE_TTL_MS));
        }
        return response;
    }

    /** Record addresses served for approved domains; the egress firewall follows them. */
    private void collectIps(List<String> ips) {
        if (allowedIpSink == null || ips.isEmpty()) return;
        synchronized (allowedAnswerIps) {
            if (allowedAnswerIps.size() >= 512) allowedAnswerIps.clear(); // bounded CDN churn
        }
        allowedAnswerIps.addAll(ips);
        ipListDirty = true;
    }

    /** Rewrite the sink file when new approved addresses have been seen. */
    private void flushAllowedIps() {
        if (!ipListDirty || allowedIpSink == null) return;
        ipListDirty = false;
        List<String> snapshot;
        synchronized (allowedAnswerIps) {
            snapshot = new ArrayList<>(allowedAnswerIps);
        }
        try {
            Files.write(allowedIpSink.toPath(),
                    (String.join("\n", snapshot) + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            ipListDirty = true;
        }
    }

    /** IPv4/IPv6 addresses carried by a successful upstream answer (A and AAAA records). */
    public static List<String> parseAnswerIps(byte[] msg) {
        List<String> out = new ArrayList<>();
        if (msg == null || msg.length < 12) return out;
        int questions = ((msg[4] & 0xFF) << 8) | (msg[5] & 0xFF);
        int answers = ((msg[6] & 0xFF) << 8) | (msg[7] & 0xFF);
        int pos = 12;
        for (int i = 0; i < questions && pos < msg.length; i++) {
            int next = skipName(msg, pos);
            if (next < 0) return out;
            pos = next + 4; // QTYPE + QCLASS
        }
        for (int i = 0; i < answers && pos + 10 <= msg.length; i++) {
            int next = skipName(msg, pos);
            if (next < 0) return out;
            pos = next;
            int type = ((msg[pos] & 0xFF) << 8) | (msg[pos + 1] & 0xFF);
            int rdlength = ((msg[pos + 8] & 0xFF) << 8) | (msg[pos + 9] & 0xFF);
            pos += 10;
            if (pos + rdlength > msg.length) return out;
            if (type == 1 && rdlength == 4) {
                out.add((msg[pos] & 0xFF) + "." + (msg[pos + 1] & 0xFF) + "."
                        + (msg[pos + 2] & 0xFF) + "." + (msg[pos + 3] & 0xFF));
            } else if (type == 28 && rdlength == 16) {
                byte[] addr = new byte[16];
                System.arraycopy(msg, pos, addr, 0, 16);
                try {
                    out.add(InetAddress.getByAddress(addr).getHostAddress());
                } catch (Exception ignored) {
                    // a malformed AAAA record is skipped, the rest still count
                }
            }
            pos += rdlength;
        }
        return out;
    }

    /** Index just past a possibly compressed name; -1 when the message is malformed. */
    private static int skipName(byte[] msg, int pos) {
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2 <= msg.length ? pos + 2 : -1;
            pos += 1 + len;
        }
        return -1;
    }

    /**
     * Cache key: the question name and type. The query ID is excluded on purpose —
     * cached answers are served with each requester's own ID written back in.
     */
    private static String cacheKey(byte[] query, String host) {
        if (host == null) return null;
        int qtype = questionType(query);
        if (qtype < 0) return null;
        return host + "/" + qtype;
    }

    /** Write the two ID bytes of {@code idSource} into a copy of {@code response}. */
    private static byte[] withQueryId(byte[] response, byte[] idSource) {
        byte[] out = response.clone();
        out[0] = idSource[0];
        out[1] = idSource[1];
        return out;
    }

    /** ANCOUNT of a DNS message, or -1 when the header is malformed. */
    private static int answerCount(byte[] msg) {
        if (msg.length < 12) return -1;
        return ((msg[6] & 0xFF) << 8) | (msg[7] & 0xFF);
    }

    /** QTYPE of the first question, or -1. */
    private static int questionType(byte[] msg) {
        if (msg.length < 12) return -1;
        int pos = 12;
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) != 0) return -1;
            pos++;
            if (pos + len > msg.length) return -1;
            pos += len;
        }
        if (pos + 4 > msg.length) return -1;
        return ((msg[pos] & 0xFF) << 8) | (msg[pos + 1] & 0xFF);
    }

    /**
     * Resolve an approved domain through a system or public resolver.
     *
     * <p>The upstream socket is CONNECTED so the kernel discards datagrams from any
     * source other than the resolver itself, and every reply is validated against
     * the request (matching ID, question name and question type) before it is used.
     * Without these checks an attacker on the exam LAN could race spoofed replies
     * and point an approved domain at a server they control.
     */
    private byte[] forward(byte[] query) {
        for (String upstream : upstreams) {
            try (DatagramSocket up = new DatagramSocket()) {
                up.setSoTimeout(UPSTREAM_TIMEOUT_MS);
                InetAddress addr = InetAddress.getByName(upstream);
                up.connect(addr, DNS_PORT);
                up.send(new DatagramPacket(query, query.length, addr, DNS_PORT));
                byte[] buf = new byte[MAX_PACKET];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                up.receive(resp);
                byte[] out = new byte[resp.getLength()];
                System.arraycopy(resp.getData(), 0, out, 0, resp.getLength());
                if (!responseMatchesQuery(out, query)) continue; // spoofed or garbled: next resolver
                return out;
            } catch (Exception ignored) {
                // try the next resolver
            }
        }
        return buildResponse(query, RCODE_SERVFAIL);
    }

    /** True when a reply is a usable answer to this exact query. */
    public static boolean responseMatchesQuery(byte[] reply, byte[] query) {
        if (reply.length < 12 || query.length < 12) return false;
        if (reply[0] != query[0] || reply[1] != query[1]) return false;   // transaction ID
        String asked = parseQName(query);
        String answered = parseQName(reply);
        if (asked == null || !asked.equals(answered)) return false;
        return questionType(reply) == questionType(query);
    }

    /**
     * Report a denied lookup. Background/telemetry lookups are dropped silently and
     * the startup settling window is quiet, so only deliberate student navigation is
     * recorded — as a NOTICE (yellow), because the block held and nothing opened.
     * A red flag stays reserved for things that actually got through.
     */
    private void recordBlocked(String host) {
        if (System.currentTimeMillis() < graceUntil) return;
        if (loggedBlockedHosts.size() >= MAX_LOGGED_HOSTS) return;

        String userFacing = reporter.userFacingViolation(host);
        if (userFacing == null || userFacing.isEmpty()) return;
        if (!loggedBlockedHosts.add(userFacing)) return;

        Violation v = new Violation("BLOCKED_INTERNET_DOMAIN", userFacing,
                Violation.Severity.NOTICE);
        logManager.record(v);
        if (listener != null) listener.onViolation(v);
    }

    // ------------------------------------------------ minimal DNS wire format

    private static final int RCODE_SERVFAIL = 2;
    private static final int RCODE_NXDOMAIN = 3;

    /** Read the first question name from a query, lower-cased. */
    public static String parseQName(byte[] msg) {
        if (msg.length < 12) return null;
        int pos = 12;
        StringBuilder sb = new StringBuilder();
        while (pos < msg.length) {
            int len = msg[pos] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) != 0) return null; // compression pointer: not a plain question
            pos++;
            if (pos + len > msg.length) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < len; i++) sb.append((char) (msg[pos + i] & 0xFF));
            pos += len;
        }
        return sb.length() == 0 ? null : sb.toString().toLowerCase(Locale.ROOT);
    }

    /** Echo the question back with the supplied RCODE and no answer records. */
    private static byte[] buildResponse(byte[] query, int rcode) {
        if (query.length < 12) return null;
        int pos = 12;
        while (pos < query.length) {
            int len = query[pos] & 0xFF;
            pos++;
            if (len == 0) break;
            pos += len;
        }
        pos += 4; // QTYPE + QCLASS
        int questionEnd = Math.min(pos, query.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(query[0]);
        out.write(query[1]);
        int rd = query[2] & 0x01;
        out.write(0x80 | rd);             // QR=1, RD copied
        out.write(0x80 | (rcode & 0x0F)); // RA=1 + RCODE
        out.write(0x00); out.write(0x01); // QDCOUNT = 1
        for (int i = 0; i < 6; i++) out.write(0x00); // AN/NS/AR = 0
        for (int i = 12; i < questionEnd; i++) out.write(query[i]);
        return out.toByteArray();
    }
}
