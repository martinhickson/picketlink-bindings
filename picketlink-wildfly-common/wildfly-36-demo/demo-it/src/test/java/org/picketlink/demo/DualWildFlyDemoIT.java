package org.picketlink.demo;

import java.nio.file.Path;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.picketlink.demo.support.DemoEnvironment;
import org.picketlink.demo.support.DemoElytronConfigurator;
import org.picketlink.demo.support.DemoWarSupport;
import org.picketlink.demo.support.WildFlyServer;

public class DualWildFlyDemoIT {

    private static WildFlyServer idpServer;
    private static WildFlyServer spServer;

    @BeforeClass
    public static void startDemo() throws Exception {
        stopStaleDemoServers();
        Path idpHome = Path.of(DemoEnvironment.IDP_JBOSS_HOME);
        Path spHome = Path.of(DemoEnvironment.SP_JBOSS_HOME);

        DemoElytronConfigurator.prepareServerHome(idpHome);
        DemoElytronConfigurator.prepareServerHome(spHome);

        idpServer = new WildFlyServer("idp", idpHome, DemoEnvironment.IDP_HOST, DemoEnvironment.MGMT_PORT);
        spServer = new WildFlyServer("sp", spHome, DemoEnvironment.SP_HOST, DemoEnvironment.MGMT_PORT);

        idpServer.start();
        spServer.start();

        DemoElytronConfigurator.configure(idpServer);
        DemoElytronConfigurator.configure(spServer);

        Path idpWar = Path.of("../demo-idp-war/target/demo-idp.war").toAbsolutePath().normalize();
        Path spWar = Path.of("../demo-sp-war/target/demo-sp.war").toAbsolutePath().normalize();
        if (!idpWar.toFile().exists() || !spWar.toFile().exists()) {
            throw new IllegalStateException("Build demo WARs first: mvn package -pl demo-idp-war,demo-sp-war -am");
        }

        Path idpKeystore = idpHome.resolve("standalone/configuration/jbid_test_keystore.jks");
        Path spKeystore = spHome.resolve("standalone/configuration/jbid_test_keystore.jks");
        idpWar = DemoWarSupport.withKeystorePath(idpWar, idpKeystore);
        spWar = DemoWarSupport.withKeystorePath(spWar, spKeystore);

        idpServer.deploy(idpWar);
        spServer.deploy(spWar);

        printDashboard();
    }

    @AfterClass
    public static void stopDemo() {
        if (!DemoEnvironment.KEEP_ALIVE) {
            if (spServer != null) {
                spServer.stop();
            }
            if (idpServer != null) {
                idpServer.stop();
            }
            stopStaleDemoServers();
        }
    }

    private static void stopStaleDemoServers() {
        try {
            new ProcessBuilder("pkill", "-f", "wildfly-36-demo/demo-it/target/wildfly").start().waitFor();
            Thread.sleep(2000);
        } catch (Exception ignored) {
        }
    }

    @Test
    public void metadataAndApiEndpointsAreReachable() throws Exception {
        try (CloseableHttpClient client = HttpClientBuilder.create().disableRedirectHandling().build()) {
            assertOk(client, DemoEnvironment.idpBaseUrl() + "metadata");
            assertOk(client, DemoEnvironment.idpBaseUrl() + "api/admin/federation/metadata");
            assertOk(client, DemoEnvironment.idpBaseUrl() + "api/info");
            assertOk(client, DemoEnvironment.spBaseUrl() + "metadata");
            assertOk(client, DemoEnvironment.spBaseUrl() + "api/admin/federation/metadata");
            assertOk(client, DemoEnvironment.spBaseUrl() + "api/info");
            assertSpRequiresSaml(client, DemoEnvironment.spBaseUrl() + "api/me");
        }

        if (DemoEnvironment.KEEP_ALIVE) {
            System.out.println();
            System.out.println("Keep-alive enabled — servers stay up for "
                    + DemoEnvironment.KEEP_ALIVE_MINUTES + " minutes. Press Ctrl+C to stop early.");
            Thread.sleep(DemoEnvironment.KEEP_ALIVE_MINUTES * 60_000L);
        }
    }

    private static void assertSpRequiresSaml(CloseableHttpClient client, String url) throws Exception {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int code = response.getStatusLine().getStatusCode();
            String location = response.getFirstHeader("Location") == null
                    ? "" : response.getFirstHeader("Location").getValue();
            Assert.assertEquals("Expected SAML redirect from " + url, 302, code);
            Assert.assertTrue("Expected redirect to IDP, got " + location,
                    location.contains(DemoEnvironment.IDP_HOST));
        }
    }

    private static void assertOk(CloseableHttpClient client, String url) throws Exception {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int code = response.getStatusLine().getStatusCode();
            String body = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity());
            Assert.assertTrue("Expected 2xx from " + url + " but got " + code + " body=" + body, code >= 200 && code < 300);
        }
    }

    private static void printDashboard() {
        System.out.println();
        System.out.println("=== PicketLink WildFly 36 Demo ===");
        System.out.println("IDP Angular UI : " + DemoEnvironment.idpAppUrl());
        System.out.println("IDP metadata   : " + DemoEnvironment.idpBaseUrl() + "metadata");
        System.out.println("IDP metadata JSON: " + DemoEnvironment.idpBaseUrl() + "api/admin/federation/metadata");
        System.out.println("IDP CXF info   : " + DemoEnvironment.idpBaseUrl() + "api/info");
        System.out.println("IDP login      : " + DemoEnvironment.idpBaseUrl() + "FormLoginServlet (user1/password1)");
        System.out.println();
        System.out.println("SP Angular UI  : " + DemoEnvironment.spAppUrl());
        System.out.println("SP secured app : " + DemoEnvironment.spAppUrl() + "secured  (triggers SAML SSO)");
        System.out.println("SP metadata    : " + DemoEnvironment.spBaseUrl() + "metadata");
        System.out.println("SP metadata JSON: " + DemoEnvironment.spBaseUrl() + "api/admin/federation/metadata");
        System.out.println("SP CXF info    : " + DemoEnvironment.spBaseUrl() + "api/info");
        System.out.println("SP session API : " + DemoEnvironment.spBaseUrl() + "api/me (secured; SPA guard)");
        System.out.println();
        System.out.println("Loopback aliases required:");
        System.out.println("  sudo ip addr add " + DemoEnvironment.IDP_HOST + "/8 dev lo");
        System.out.println("  sudo ip addr add " + DemoEnvironment.SP_HOST + "/8 dev lo");
        System.out.println();
    }
}
