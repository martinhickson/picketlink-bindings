package org.picketlink.demo;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.picketlink.demo.support.DemoOidcElytronConfigurator;
import org.picketlink.demo.support.OidcDemoEnvironment;
import org.picketlink.demo.support.WildFlyServer;
import java.nio.file.Files;
import java.nio.file.Path;

public class DualWildFlyOidcDemoIT {

    private static WildFlyServer asServer;
    private static WildFlyServer rpServer;

    @BeforeClass
    public static void startDemo() throws Exception {
        stopStaleDemoServers();
        Path asHome = Path.of(OidcDemoEnvironment.AS_JBOSS_HOME);
        Path rpHome = Path.of(OidcDemoEnvironment.RP_JBOSS_HOME);

        DemoOidcElytronConfigurator.prepareServerHome(asHome);
        DemoOidcElytronConfigurator.prepareServerHome(rpHome);

        String keystoreAgent = resolveKeystoreAgentJar();
        if (keystoreAgent != null) {
            System.setProperty("picketlink.oidc.keystore.agent", keystoreAgent);
        }

        asServer = new WildFlyServer("as", asHome, OidcDemoEnvironment.AS_HOST, OidcDemoEnvironment.MGMT_PORT);
        rpServer = new WildFlyServer("rp", rpHome, OidcDemoEnvironment.RP_HOST, OidcDemoEnvironment.MGMT_PORT);

        asServer.start();
        rpServer.start();

        DemoOidcElytronConfigurator.configureAs(asServer);

        Path asWar = Path.of("../demo-as-war/target/demo-as.war").toAbsolutePath().normalize();
        Path rpWar = Path.of("../demo-rp-war/target/demo-rp.war").toAbsolutePath().normalize();
        if (!asWar.toFile().exists() || !rpWar.toFile().exists()) {
            throw new IllegalStateException("Build demo WARs first: mvn package -pl demo-as-war,demo-rp-war -am");
        }

        asServer.deploy(asWar);
        rpServer.deploy(rpWar);

        printDashboard();
    }

    @AfterClass
    public static void stopDemo() {
        if (!OidcDemoEnvironment.KEEP_ALIVE) {
            if (rpServer != null) {
                rpServer.stop();
            }
            if (asServer != null) {
                asServer.stop();
            }
            stopStaleDemoServers();
        }
    }

    private static void stopStaleDemoServers() {
        try {
            new ProcessBuilder("pkill", "-9", "-f", "wildfly-36-oidc-demo/demo-it/target/wildfly").start().waitFor();
            new ProcessBuilder("pkill", "-9", "-f", "wildfly-36-demo/demo-it/target/wildfly").start().waitFor();
            Thread.sleep(2000);
        } catch (Exception ignored) {
        }
    }

    private static String resolveKeystoreAgentJar() {
        Path agent = Path.of("target/picketlink-oidc-keystore-agent.jar").toAbsolutePath().normalize();
        return Files.isRegularFile(agent) ? agent.toString() : null;
    }

    @Test
    public void oidcDiscoveryAndApiEndpointsAreReachable() throws Exception {
        try (CloseableHttpClient client = HttpClientBuilder.create().disableRedirectHandling().build()) {
            assertOk(client, OidcDemoEnvironment.asBaseUrl() + ".well-known/openid-configuration");
            assertOk(client, OidcDemoEnvironment.asBaseUrl() + "api/info");
            assertOk(client, OidcDemoEnvironment.rpBaseUrl() + "api/info");
            assertRpRequiresOidc(client, OidcDemoEnvironment.rpBaseUrl() + "api/me");
        }

        if (OidcDemoEnvironment.KEEP_ALIVE) {
            System.out.println();
            System.out.println("Keep-alive enabled — servers stay up for "
                    + OidcDemoEnvironment.KEEP_ALIVE_MINUTES + " minutes. Press Ctrl+C to stop early.");
            Thread.sleep(OidcDemoEnvironment.KEEP_ALIVE_MINUTES * 60_000L);
        }
    }

    private static void assertRpRequiresOidc(CloseableHttpClient client, String url) throws Exception {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int code = response.getStatusLine().getStatusCode();
            String location = response.getFirstHeader("Location") == null
                    ? "" : response.getFirstHeader("Location").getValue();
            Assert.assertTrue("Expected OIDC redirect from " + url + " but got " + code,
                    code == 302 || code == 303);
            Assert.assertTrue("Expected redirect to AS authorize, got " + location,
                    location.contains(OidcDemoEnvironment.AS_HOST)
                            && location.contains("/oidc/authorize"));
        }
    }

    private static void assertOk(CloseableHttpClient client, String url) throws Exception {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int code = response.getStatusLine().getStatusCode();
            String body = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity());
            Assert.assertTrue("Expected 2xx from " + url + " but got " + code + " body=" + body,
                    code >= 200 && code < 300);
        }
    }

    private static void printDashboard() {
        System.out.println();
        System.out.println("=== PicketLink WildFly 36 OIDC Demo ===");
        System.out.println("Authorization Server (producer): " + OidcDemoEnvironment.asBaseUrl());
        System.out.println("  Discovery: " + OidcDemoEnvironment.asBaseUrl() + ".well-known/openid-configuration");
        System.out.println("  Admin UI:  " + OidcDemoEnvironment.asAppUrl() + "admin");
        System.out.println("Relying Party (consumer):      " + OidcDemoEnvironment.rpBaseUrl());
        System.out.println("  Secured UI:" + OidcDemoEnvironment.rpAppUrl() + "secured");
        System.out.println("Login at AS: user1 / password1");
        System.out.println();
    }
}
