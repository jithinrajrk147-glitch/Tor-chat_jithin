package com.torchat;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.torproject.jni.TorService;

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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * TorChatto Tor plugin — corrected version.
 *
 * v1 of this file tried to exec a standalone "tor" binary via ProcessBuilder.
 * That was wrong: info.guardianproject:tor-android does not ship a
 * standalone executable at all. Tor is compiled in as a JNI shared library
 * (System.loadLibrary("tor") inside the library's own
 * org.torproject.jni.TorService class) and runs IN-PROCESS inside that
 * Android Service. There is no separate binary file to find or launch.
 *
 * The correct integration, confirmed against the real library source
 * (guardianproject/tor-android, tor-android-binary/.../jni/TorService.java):
 *   1. Before starting the service, write our own hidden-service directives
 *      into the OPTIONAL torrc file at TorService.getTorrc(context) — the
 *      service reads this file itself via "-f <torrc>" when it launches Tor.
 *      (Base config like DataDirectory/ControlSocket/SocksPort is already
 *      supplied by the service itself; we only add HiddenServiceDir/Port.)
 *   2. bindService(new Intent(context, TorService.class), ..., BIND_AUTO_CREATE)
 *      — this triggers the service's onCreate(), which starts the Tor thread.
 *   3. Listen for the TorService.ACTION_STATUS broadcast for user-facing
 *      progress text.
 *   4. Poll for the hidden service's "hostname" file the same way any Tor
 *      hidden service integration does — Tor writes it once the service's
 *      keys/descriptor are ready.
 *   5. Read the real SOCKS port back from the bound TorService instance via
 *      getSocksPort() (the library may fall back to a random "auto" port if
 *      9050 is already taken on the device), instead of hardcoding 9050.
 *
 * Gradle (see .github/workflows/build-apk.yml):
 *   implementation 'info.guardianproject:tor-android:0.4.8.18'
 *   implementation 'info.guardianproject:jtorctl:0.4.5.7'
 *   implementation 'androidx.localbroadcastmanager:localbroadcastmanager:1.1.0'
 * Repositories: maven { url 'https://raw.githubusercontent.com/guardianproject/gpmaven/master' }
 */
@CapacitorPlugin(name = "TorChat")
public class TorPlugin extends Plugin {

    private static final String TAG = "TorChatto";
    private static final int HS_LOCAL_PORT = 8080;

    private TorService torService;
    private ServerSocket inboundServer;
    private Socket peerSocket;
    private OutputStream peerOut;
    private final AtomicBoolean serverListening = new AtomicBoolean(false);

    private String onionAddress = null;
    private String linkHash = null;
    private File hsDir;

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String status = intent.getStringExtra(TorService.EXTRA_STATUS);
            if (status != null) {
                notifyStatus(status);
            }
        }
    };

    // ---------------------------------------------------------------
    // startTor
    // ---------------------------------------------------------------
    @PluginMethod
    public void startTor(PluginCall call) {
        new Thread(() -> {
            try {
                Context ctx = getContext().getApplicationContext();

                hsDir = new File(ctx.getFilesDir(), "torchatto_hidden_service");
                hsDir.mkdirs();
                hsDir.setReadable(false, false);
                hsDir.setWritable(false, false);
                hsDir.setExecutable(false, false);
                hsDir.setReadable(true, true);
                hsDir.setWritable(true, true);
                hsDir.setExecutable(true, true);

                // Write ONLY our extra directives — TorService itself already
                // supplies DataDirectory/ControlSocket/CookieAuthentication/etc
                // on the command line before reading this file.
                File torrc = TorService.getTorrc(ctx);
                try (FileWriter w = new FileWriter(torrc, false)) {
                    w.write("HiddenServiceDir " + hsDir.getAbsolutePath() + "\n");
                    w.write("HiddenServicePort 80 127.0.0.1:" + HS_LOCAL_PORT + "\n");
                }

                ctx.registerReceiver(statusReceiver, new IntentFilter(TorService.ACTION_STATUS));
                notifyStatus("binding tor service");

                CountDownLatch boundLatch = new CountDownLatch(1);
                ServiceConnection connection = new ServiceConnection() {
                    @Override
                    public void onServiceConnected(ComponentName name, IBinder binder) {
                        torService = ((TorService.LocalBinder) binder).getService();
                        boundLatch.countDown();
                    }

                    @Override
                    public void onServiceDisconnected(ComponentName name) {
                        torService = null;
                    }
                };

                Intent serviceIntent = new Intent(ctx, TorService.class);
                boolean bound = ctx.bindService(serviceIntent, connection, Context.BIND_AUTO_CREATE);
                if (!bound) {
                    throw new IOException("bindService(TorService) returned false — check the service is declared in the manifest (should be auto-merged from the tor-android AAR)");
                }
                if (!boundLatch.await(20, TimeUnit.SECONDS)) {
                    throw new IOException("timed out binding to TorService");
                }

                // Hostname file appears once Tor has generated the hidden
                // service's keys and descriptor. Give it plenty of time —
                // first-run bootstrap can take 15-90s on a slow network.
                File hostnameFile = new File(hsDir, "hostname");
                waitForFile(hostnameFile, 120_000);

                String hostname = readFirstLine(hostnameFile).trim();
                onionAddress = hostname;
                linkHash = shortHash(hostname);

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

    private void waitForFile(File f, long timeoutMs) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        while (!f.exists() || f.length() == 0) {
            if (System.currentTimeMillis() - start > timeoutMs) {
                throw new IOException("timed out waiting for " + f.getName() +
                        " — check logcat tag TorService for what Tor itself reported");
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

    /** Short, human-shareable fingerprint appended after '#' in the link — a UX check-digit, not used by Tor itself. */
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
        if (torService == null) {
            call.reject("Tor is not running yet");
            return;
        }

        new Thread(() -> {
            try {
                int socksPort = torService.getSocksPort();
                if (socksPort <= 0) {
                    throw new IOException("Tor has no active SOCKS port yet");
                }

                Socket socksSocket = new Socket();
                socksSocket.connect(new InetSocketAddress("127.0.0.1", socksPort), 30_000);

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
        try { getContext().getApplicationContext().unregisterReceiver(statusReceiver); } catch (Exception ignored) {}
        super.handleOnDestroy();
    }
}
