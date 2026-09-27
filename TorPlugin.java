package com.torchat;

import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
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

    private String onionAddress;
    private String linkHash;

    @PluginMethod
    public void startTor(PluginCall call) {
        new Thread(() -> {
            try {
                if (getContext() == null) {
                    throw new IllegalStateException("Android context is unavailable");
                }

                File baseDir = new File(getContext().getFilesDir(), "tor");
                File dataDir = new File(baseDir, "data");
                File hsDir = new File(baseDir, "hidden_service");
                if (!dataDir.mkdirs() && !dataDir.isDirectory()) {
                    throw new IOException("Unable to create Tor data dir: " + dataDir.getAbsolutePath());
                }
                if (!hsDir.mkdirs() && !hsDir.isDirectory()) {
                    throw new IOException("Unable to create hidden service dir: " + hsDir.getAbsolutePath());
                }

                secureDir(hsDir);

                File torrc = writeTorrc(baseDir, dataDir, hsDir);
                String torBinaryPath = locateTorBinary();

                notifyStatus("launching tor binary");

                ProcessBuilder pb = new ProcessBuilder(torBinaryPath, "-f", torrc.getAbsolutePath());
                pb.redirectErrorStream(true);
                pb.environment().put("HOME", getContext().getFilesDir().getAbsolutePath());
                torProcess = pb.start();
                drainTorLog(torProcess.getInputStream());

                waitForProcessToStayAlive(2000);
                File hostnameFile = new File(hsDir, "hostname");
                waitForFile(hostnameFile, 90_000);

                String hostname = readFirstLine(hostnameFile).trim();
                if (hostname.isEmpty() || !hostname.endsWith(".onion")) {
                    throw new IOException("Tor generated an invalid .onion hostname: " + hostname);
                }

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

    private void secureDir(File dir) {
        dir.setReadable(false, false);
        dir.setWritable(false, false);
        dir.setExecutable(false, false);
        dir.setReadable(true, true);
        dir.setWritable(true, true);
        dir.setExecutable(true, true);
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
        }
        return torrc;
    }

    private String locateTorBinary() throws IOException {
        String nativeDir = getContext().getApplicationInfo().nativeLibraryDir;
        String[] candidates = {"libTor.so", "libtor.so"};
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
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.d(TAG, "[tor] " + line);
                    if (line.contains("Bootstrapped")) {
                        notifyStatus(line.substring(line.indexOf("Bootstrapped")));
                    }
                }
            } catch (IOException ignored) {
            }
        }, "torchatto-tor-log").start();
    }

    private void waitForProcessToStayAlive(long timeoutMs) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        while (torProcess != null && torProcess.isAlive() && (System.currentTimeMillis() - start) < timeoutMs) {
            Thread.sleep(100);
        }
        if (torProcess == null || !torProcess.isAlive()) {
            int exitCode = (torProcess == null) ? -1 : torProcess.exitValue();
            throw new IOException("tor process exited early with exit code " + exitCode);
        }
    }

    private void waitForFile(File file, long timeoutMs) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        while (!file.exists() || file.length() == 0L) {
            if (torProcess == null || !torProcess.isAlive()) {
                throw new IOException("tor process exited before publishing hidden service");
            }
            if (System.currentTimeMillis() - start > timeoutMs) {
                throw new IOException("timed out waiting for " + file.getName());
            }
            Thread.sleep(300);
        }
    }

    private String readFirstLine(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("empty hostname file");
            }
            return line;
        }
    }

    private String shortHash(String onion) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(onion.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            sb.append(String.format("%02x", digest[i] & 0xFF));
        }
        return sb.toString();
    }

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

                BufferedReader reader = new BufferedReader(new InputStreamReader(incoming.getInputStream(), StandardCharsets.UTF_8));
                String line;
                while ((line = reader.readLine()) != null) {
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

                out.write(new byte[]{0x05, 0x01, 0x00});
                out.flush();
                byte[] greetReply = readNBytes(in, 2);
                if (greetReply[0] != 0x05 || greetReply[1] != 0x00) {
                    throw new IOException("SOCKS5 handshake rejected (server wants auth we don't support)");
                }

                byte[] hostBytes = onion.getBytes(StandardCharsets.US_ASCII);
                int port = 80;

                java.io.ByteArrayOutputStream req = new java.io.ByteArrayOutputStream();
                req.write(0x05);
                req.write(0x01);
                req.write(0x00);
                req.write(0x03);
                req.write(hostBytes.length);
                req.write(hostBytes);
                req.write((port >> 8) & 0xFF);
                req.write(port & 0xFF);
                out.write(req.toByteArray());
                out.flush();

                byte[] head = readNBytes(in, 4);
                if (head[0] != 0x05) {
                    throw new IOException("bad SOCKS5 reply version");
                }
                int rep = head[1] & 0xFF;
                if (rep != 0x00) {
                    throw new IOException("SOCKS5 CONNECT failed, reply code " + rep + " (peer .onion may be offline or unreachable)");
                }
                int atyp = head[3] & 0xFF;
                if (atyp == 0x01) {
                    readNBytes(in, 4 + 2);
                } else if (atyp == 0x03) {
                    int len = readNBytes(in, 1)[0] & 0xFF;
                    readNBytes(in, len + 2);
                } else if (atyp == 0x04) {
                    readNBytes(in, 16 + 2);
                } else {
                    throw new IOException("unknown SOCKS5 ATYP " + atyp);
                }

                peerSocket = socksSocket;
                peerOut = out;
                torRunning.set(true);
                notifyPeerConnected();

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
            if (read < 0) {
                throw new IOException("SOCKS stream closed early");
            }
            total += read;
        }
        return buf;
    }

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
        if (torProcess != null) {
            torProcess.destroy();
        }
        super.handleOnDestroy();
    }
                }
