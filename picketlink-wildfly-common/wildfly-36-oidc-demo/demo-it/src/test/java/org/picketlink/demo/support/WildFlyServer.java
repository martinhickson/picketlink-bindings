package org.picketlink.demo.support;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class WildFlyServer {

    /**
     * {@code $1} JBOSS_HOME, {@code $2} agent jar, {@code $3} bridge jar, then {@code standalone.sh}.
     * The bridge jar is on the boot classpath so the deployment and the agent share one class.
     * {@code MODULE_OPTS} makes WildFly install the log manager before it runs the agent.
     */
    static final String AGENT_LAUNCH = """
            export JBOSS_HOME="$1"
            AGENT="$2"
            BRIDGE="$3"
            shift 3
            case ",${JBOSS_MODULES_SYSTEM_PKGS:-org.jboss.byteman}," in
              *,org.picketlink.oidc.keystore.bridge,*) ;;
              *) export JBOSS_MODULES_SYSTEM_PKGS="${JBOSS_MODULES_SYSTEM_PKGS:-org.jboss.byteman},org.picketlink.oidc.keystore.bridge" ;;
            esac
            export MODULE_OPTS="-javaagent:${AGENT}"
            unset JAVA_OPTS
            . "$JBOSS_HOME/bin/standalone.conf"
            JAVA_OPTS="-Xbootclasspath/a:${BRIDGE} ${JAVA_OPTS}"
            export JAVA_OPTS
            exec "$@"
            """;

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
        String keystoreAgent = System.getProperty("picketlink.oidc.keystore.agent");
        ProcessBuilder builder = new ProcessBuilder();
        List<String> command = new ArrayList<>();
        command.add(standalone.toString());
        command.add("-b");
        command.add(bindAddress);
        command.add("-bmanagement");
        command.add(bindAddress);
        command.add("-Djboss.socket.binding.port-offset=" + portOffset);
        command.add("-Dpicketlink.test.keystore.path=" + keystore);
        if (keystoreAgent != null && !keystoreAgent.isBlank() && Files.exists(Path.of(keystoreAgent))) {
            Path bridge = Path.of(keystoreAgent).resolveSibling("picketlink-oidc-keystore-bridge.jar");
            command.add(0, bridge.toString());
            command.add(0, keystoreAgent);
            command.add(0, jbossHome.toString());
            command.add(0, "bash");
            command.add(0, AGENT_LAUNCH);
            command.add(0, "-c");
            command.add(0, "bash");
        }
        builder.command(command);
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
