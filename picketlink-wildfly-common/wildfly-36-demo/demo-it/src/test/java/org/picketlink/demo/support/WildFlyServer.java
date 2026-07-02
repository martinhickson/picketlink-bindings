package org.picketlink.demo.support;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public final class WildFlyServer {

    private final String name;
    private final Path jbossHome;
    private final String bindAddress;
    private final int mgmtPort;
    private Process process;

    public WildFlyServer(String name, Path jbossHome, String bindAddress, int mgmtPort) {
        this.name = name;
        this.jbossHome = jbossHome;
        this.bindAddress = bindAddress;
        this.mgmtPort = mgmtPort;
    }

    public void start() throws Exception {
        start(0);
    }

    public void start(int portOffset) throws Exception {
        if (process != null && process.isAlive()) {
            return;
        }
        Path standalone = jbossHome.resolve("bin/standalone.sh");
        if (!Files.exists(standalone)) {
            throw new IllegalStateException("Missing WildFly at " + jbossHome);
        }
        Path keystore = jbossHome.resolve("standalone/configuration/jbid_test_keystore.jks");
        Path jaasConfig = jbossHome.resolve("standalone/configuration/picketlink-sp.login.conf");
        ProcessBuilder builder = new ProcessBuilder(
                standalone.toString(),
                "-b", bindAddress,
                "-bmanagement", bindAddress,
                "-Djboss.socket.binding.port-offset=" + portOffset,
                "-Dpicketlink.test.keystore.path=" + keystore,
                "-Djava.security.auth.login.config=" + jaasConfig);
        builder.directory(jbossHome.toFile());
        builder.environment().put("JBOSS_HOME", jbossHome.toString());
        builder.redirectErrorStream(true);
        process = builder.start();
        drainOutput(process.getInputStream(), name);
        waitForManagement(Duration.ofMinutes(3));
        System.out.println("[" + name + "] WildFly started on " + bindAddress + " (mgmt " + mgmtPort + ")");
    }

    public void stop() {
        if (process != null && process.isAlive()) {
            process.destroy();
            try {
                process.waitFor(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
        }
    }

    public void deploy(Path war) throws Exception {
        Path cli = jbossHome.resolve("bin/jboss-cli.sh");
        runCli(cli, bindAddress, mgmtPort,
                "deploy " + war.toAbsolutePath() + " --force");
        System.out.println("[" + name + "] Deployed " + war.getFileName());
    }

    public Path jbossHome() {
        return jbossHome;
    }

    public String bindAddress() {
        return bindAddress;
    }

    private void waitForManagement(Duration timeout) throws Exception {
        Path cli = jbossHome.resolve("bin/jboss-cli.sh");
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() < deadline) {
            try {
                runCli(cli, bindAddress, mgmtPort, ":read-attribute(name=server-state)");
                return;
            } catch (Exception ignored) {
                Thread.sleep(2000);
            }
        }
        throw new IllegalStateException("Timed out waiting for " + name + " management on " + bindAddress);
    }

    private static void runCli(Path cli, String bindAddress, int mgmtPort, String command)
            throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(
                cli.toString(),
                "--controller=" + bindAddress + ":" + mgmtPort,
                "--connect",
                "--command=" + command);
        builder.redirectErrorStream(true);
        Process cliProcess = builder.start();
        String output;
        try (InputStream in = cliProcess.getInputStream()) {
            output = new String(in.readAllBytes());
        }
        int exit = cliProcess.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("CLI failed (" + exit + "): " + command + "\n" + output);
        }
    }

    private static void drainOutput(InputStream stream, String prefix) {
        Thread t = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[" + prefix + "] " + line);
                }
            } catch (IOException ignored) {
            }
        }, prefix + "-log");
        t.setDaemon(true);
        t.start();
    }
}
