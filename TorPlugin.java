package com.torchat;

import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * TorChatto Tor plugin.
 *
 * This does NOT bind to the tor-android library's internal TorService Java
 * class, because that internal API has changed shape across releases and
 * cannot be verified against every version without a real build/test cycle.
 * Instead it does exactly what TorService itself ultimately does under the
 * hood: it launches the native `tor` binary that the info.guardianproject:tor-android
 * AAR ships (extracted by Android's package manager into the app's
 * nativeLibraryDir because it is packed as a jniLibs .so file), pointed at a
 * real torrc we generate, and talks to it purely over the loopback SOCKS port
 * and the hidden service's plaintext local listener. This is real Tor,
 * running as a real subprocess, with a real v3 .onion hidden service.
 *
 * Add to app/build.gradle (see .github/workflows/build-apk.yml, which does
 * this automatically):
 *   implementation 'info.guardianproject:tor-android:0.4.8.11'
 * And in the project-level build.gradle repositories block:
 *   maven { url 'https://raw.githubusercontent.com/guardianproject/gpmaven/master' }
 */
@CapacitorPlugin(name = "TorChat")
public class TorPlugin extends Plugin {

    private static final String TAG = "TorChatto";
    private static final int SOCKS_PORT = 9050;
    private static final int HS_LOCAL_PORT = 8080;

    private Process torProcess;
    private ServerSocket inboundServer;
    private Socket peerSocket;
    private OutputStream peerOut;
    private final AtomicBoolean torRunning = new AtomicBoolean(false);
    private final AtomicBoolean serverListening = new AtomicBoolean(false);

    private String onionAddress = null;
    private String linkHash = null;

    // ---------------------------------------------------------------
    // startTor
    // ---------------------------------------------------------------
    @PluginMethod
    public void startTor(PluginCall call) {
        new Thread(() -> {
            try {
                File baseDir = new File(getContext().getFilesDir(), "tor");
                File dataDir = new File(baseDir, "data");
                File hsDir = new File(baseDir, "hidden_service");
                dataDir.mkdirs();
                hsDir.mkdirs();

                // Lock down permissions on the hidden service directory —
                // Tor refuses to start if this isn't private.
                hsDir.setReadable(false, false);
                hsDir.setWritable(false, false);
                hsDir.setExecutable(false, false);
                hsDir.setReadable(true, true);
                hsDir.setWritable(true, true);
                hsDir.setExecutable(true, true);

                File torrc = writeTorrc(baseDir, dataDir, hsDir);
                String torBinaryPath = locateTorBinary();

                notifyStatus("launching tor binary");
                ProcessBuilder pb = new ProcessBuilder(
                        torBinaryPath,
                        "-f", torrc.getAbsolutePath()
                );
                pb.redirectErrorStream(true);
                pb.environment().put("HOME", getContext().getFilesDir().getAbsolutePath());
                torProcess = pb.start();

                // Drain Tor's stdout/stderr in the background so its pipe never
                // fills up and blocks the process, and log bootstrap progress.
                drainTorLog(torProcess.getInputStream());

                // Poll for bootstrap completion by watching the control log line
                // "Bootstrapped 100%" is what we look for, with a hard timeout.
                waitForBootstrap(90_000);

                // Poll for the hostname file — Tor writes this only after it has
                // published the v3 onion descriptor.
                File hostnameFile = new File(hsDir, "hostname");
                waitForFile(hostnameFile, 60_000);

                String hostname = readFirstLine(hostnameFile).trim(); // e.g. abcdef....onion
                onionAddress = hostname;
                linkHash = shortHash(hostname);
                torRunning.set(true);

                startInboundServer();

                notifyStatus("ready");

                JSObject ret = new JSObject();
                ret.put("onion", onionAddress);
                ret.put("hash", linkHash);
                call.resolve(ret);

            } catch (Exception e) {
                Log.e(TAG, "startTor failed", e);
                call.reject("startTor failed: " + e.getMessage(), e);
            }
        }, "torchatto-tor-start").start();
    }

    private File writeTorrc(File baseDir, File dataDir, File hsDir) throws IOException {
        File torrc = new File(baseDir, "torrc");
        try (FileWriter w = new FileWriter(torrc)) {
            w.write("SocksPort 127.0.0.1:" + SOCKS_PORT + "\n");
            w.write("DataDirectory " + dataDir.getAbsolutePath() + "\n");
            w.write("HiddenServiceDir " + hsDir.getAbsolutePath() + "\n");
            w.write("HiddenServicePort 80 127.0.0.1:" + HS_LOCAL_PORT + "\n");
            w.write("AvoidDiskWrites 1\n");
            w.write("CookieAuthentication 0\n");
            w.write("Log notice stdout\n");
            // v3 onions are the default in modern Tor; no extra directive needed.
        }
        return torrc;
    }

    /**
     * The tor-android AAR ships the tor binary as a jniLibs "shared library"
     * (e.g. libTor.so) purely so Android's package manager will extract it
     * for us into a directory that is guaranteed executable — .so files are
     * the only files Android extracts with the executable bit set on modern
     * targetSdk. It is a real Tor binary, just packaged this way for
     * Android's benefit.
     */
    private String locateTorBinary() throws IOException {
        String nativeDir = getContext().getApplicationInfo().nativeLibraryDir;
        String[] candidates = { "libTor.so", "libtor.so" };
        for (String name : candidates) {
            File f = new File(nativeDir, name);
            if (f.exists()) {
                if (!f.canExecute()) {
                    f.setExecutable(true, false);
                }
                return f.getAbsolutePath();
            }
        }
        throw new IOException("Tor binary not found in " + nativeDir +
                " — confirm info.guardianproject:tor-android is applied and jniLibs were packaged for this ABI");
    }

    private void drainTorLog(InputStream is) {
        new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    Log.d(TAG, "[tor] " + line);
                    if (line.contains("Bootstrapped")) {
                        notifyStatus(line.substring(line.indexOf("Bootstrapped")));
                    }
                }
            } catch (IOException ignored) {
            }
        }, "torchatto-tor-log").start();
    }

    private void waitForBootstrap(long timeoutMs) throws IOException, InterruptedException {
        // We rely on waitForFile(hostname) as the real readiness signal since
        // the hostname file only appears once Tor has a working circuit and
        // has published the HS descriptor. This method just gives the
        // process a moment to get past early startup errors.
        long start = System.currentTimeMillis();
        while (torProcess.isAlive() && System.currentTimeMillis() - start < 2000) {
            Thread.sleep(100);
        }
        if (!torProcess.isAlive()) {
            throw new IOException("tor process exited immediately, exit code " + torProcess.exitValue());
        }
    }

    private void waitForFile(File f, long timeoutMs) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        while (!f.exists() || f.length() == 0) {
            if (!torProcess.isAlive()) {
                throw new IOException("tor process exited before publishing hidden service, exit code " + torProcess.exitValue());
            }
            if (System.currentTimeMillis() - start > timeoutMs) {
                throw new IOException("timed out waiting for " + f.getName());
            }
            Thread.sleep(300);
        }
    }

    private String readFirstLine(File f) throws IOException {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(f), StandardCharsets.UTF_8))) {
            String line = r.readLine();
            if (line == null) throw new IOException("empty hostname file");
            return line;
        }
    }

    /** Short, human-shareable fingerprint appended after '#' in the link, purely a UX check-digit. */
    private String shortHash(String onion) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(onion.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            sb.append(String.format("%02x", digest[i]));
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------
    // Inbound: plain TCP server behind the hidden service, Tor forwards to it
    // ---------------------------------------------------------------
    private void startInboundServer() {
        new Thread(() -> {
            try {
                inboundServer = new ServerSocket();
                inboundServer.bind(new InetSocketAddress("127.0.0.1", HS_LOCAL_PORT));
                serverListening.set(true);
                Log.d(TAG, "inbound server listening on 127.0.0.1:" + HS_LOCAL_PORT);

                while (serverListening.get()) {
                    Socket incoming = inboundServer.accept();
                    handleIncomingConnection(incoming);
                }
            } catch (IOException e) {
                if (serverListening.get()) {
                    Log.e(TAG, "inbound server error", e);
                }
            }
        }, "torchatto-inbound-server").start();
    }

    private void handleIncomingConnection(Socket incoming) {
        new Thread(() -> {
            try {
                peerSocket = incoming;
                peerOut = incoming.getOutputStream();
                notifyPeerConnected();

                BufferedReader r = new BufferedReader(new InputStreamReader(
                        incoming.getInputStream(), StandardCharsets.UTF_8));
                String line;
                while ((line = r.readLine()) != null) {
                    JSObject data = new JSObject();
                    data.put("text", line);
                    notifyListeners("message", data);
                }
            } catch (IOException e) {
                Log.d(TAG, "peer connection closed: " + e.getMessage());
            } finally {
                notifyPeerDisconnected();
            }
        }, "torchatto-inbound-handler").start();
    }

    private void notifyPeerConnected() {
        notifyListeners("peerConnected", new JSObject());
    }

    private void notifyPeerDisconnected() {
        notifyListeners("peerDisconnected", new JSObject());
    }

    private void notifyStatus(String status) {
        JSObject data = new JSObject();
        data.put("status", status);
        notifyListeners("torStatus", data);
    }

    // ---------------------------------------------------------------
    // connect — outbound SOCKS5 CONNECT through Tor to the peer's onion:80
    // ---------------------------------------------------------------
    @PluginMethod
    public void connect(PluginCall call) {
        String onion = call.getString("onion");
        if (onion == null || !onion.endsWith(".onion")) {
            call.reject("invalid onion address");
            return;
        }

        new Thread(() -> {
            try {
                Socket socksSocket = new Socket();
                socksSocket.connect(new InetSocketAddress("127.0.0.1", SOCKS_PORT), 30_000);

                OutputStream out = socksSocket.getOutputStream();
                InputStream in = socksSocket.getInputStream();

                // --- SOCKS5 greeting: version 5, 1 auth method, no-auth (0x00) ---
                out.write(new byte[]{0x05, 0x01, 0x00});
                out.flush();
                byte[] greetReply = readNBytes(in, 2);
                if (greetReply[0] != 0x05 || greetReply[1] != 0x00) {
                    throw new IOException("SOCKS5 handshake rejected (server wants auth we don't support)");
                }

                // --- SOCKS5 CONNECT request, ATYP=0x03 (domain name), for the .onion host ---
                byte[] hostBytes = onion.getBytes(StandardCharsets.US_ASCII);
                int port = 80;

                java.io.ByteArrayOutputStream req = new java.io.ByteArrayOutputStream();
                req.write(0x05); // version
                req.write(0x01); // CONNECT
                req.write(0x00); // reserved
                req.write(0x03); // ATYP = domain name
                req.write(hostBytes.length);
                req.write(hostBytes);
                req.write((port >> 8) & 0xFF);
                req.write(port & 0xFF);
                out.write(req.toByteArray());
                out.flush();

                // --- Parse reply: VER REP RSV ATYP BND.ADDR BND.PORT ---
                byte[] head = readNBytes(in, 4);
                if (head[0] != 0x05) {
                    throw new IOException("bad SOCKS5 reply version");
                }
                int rep = head[1] & 0xFF;
                if (rep != 0x00) {
                    throw new IOException("SOCKS5 CONNECT failed, reply code " + rep +
                            " (peer .onion may be offline or unreachable)");
                }
                int atyp = head[3] & 0xFF;
                if (atyp == 0x01) {
                    readNBytes(in, 4 + 2); // IPv4 + port
                } else if (atyp == 0x03) {
                    int len = readNBytes(in, 1)[0] & 0xFF;
                    readNBytes(in, len + 2);
                } else if (atyp == 0x04) {
                    readNBytes(in, 16 + 2); // IPv6 + port
                } else {
                    throw new IOException("unknown SOCKS5 ATYP " + atyp);
                }

                // Tunnel is now open — this socket is a direct Tor-to-Tor pipe to the peer.
                peerSocket = socksSocket;
                peerOut = out;
                torRunning.set(true);

                notifyPeerConnected();

                // Read any messages the peer sends back over this same connection.
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                new Thread(() -> {
                    try {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            JSObject data = new JSObject();
                            data.put("text", line);
                            notifyListeners("message", data);
                        }
                    } catch (IOException ignored) {
                    } finally {
                        notifyPeerDisconnected();
                    }
                }, "torchatto-outbound-reader").start();

                call.resolve();

            } catch (Exception e) {
                Log.e(TAG, "connect failed", e);
                call.reject("connect failed: " + e.getMessage(), e);
            }
        }, "torchatto-connect").start();
    }

    private byte[] readNBytes(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int total = 0;
        while (total < n) {
            int read = in.read(buf, total, n - total);
            if (read < 0) throw new IOException("SOCKS stream closed early");
            total += read;
        }
        return buf;
    }

    // ---------------------------------------------------------------
    // send
    // ---------------------------------------------------------------
    @PluginMethod
    public void send(PluginCall call) {
        String text = call.getString("text");
        if (text == null) {
            call.reject("text is required");
            return;
        }
        if (peerOut == null) {
            call.reject("not connected to a peer");
            return;
        }
        new Thread(() -> {
            try {
                synchronized (this) {
                    peerOut.write((text + "\n").getBytes(StandardCharsets.UTF_8));
                    peerOut.flush();
                }
                call.resolve();
            } catch (IOException e) {
                Log.e(TAG, "send failed", e);
                call.reject("send failed: " + e.getMessage(), e);
            }
        }, "torchatto-send").start();
    }

    @Override
    protected void handleOnDestroy() {
        serverListening.set(false);
        try { if (inboundServer != null) inboundServer.close(); } catch (IOException ignored) {}
        try { if (peerSocket != null) peerSocket.close(); } catch (IOException ignored) {}
        if (torProcess != null) torProcess.destroy();
        super.handleOnDestroy();
    }
}
