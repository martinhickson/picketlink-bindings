package org.picketlink.demo.support;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.dmr.ModelNode;

public final class DemoOidcElytronConfigurator {

    private static final String PROPERTIES_REALM = "PicketLinkOidcAsRealm";
    private static final String HTTP_AUTH_FACTORY = "PicketLinkOidcAsHttpAuth";
    private static final String AS_SECURITY_DOMAIN = "PicketLinkOidcAsDomain";
    private static final String AS_ELYTRON_DOMAIN = "PicketLinkOidcAsElytronDomain";

    private DemoOidcElytronConfigurator() {
    }

    public static void configureAs(WildFlyServer server) throws Exception {
        prepareServerHome(server.jbossHome());
        try (ModelControllerClient client = ModelControllerClient.Factory.create(
                java.net.InetAddress.getByName(server.bindAddress()), OidcDemoEnvironment.MGMT_PORT)) {
            removeIfExists(client, undertowAppSecurityDomainAddress(AS_SECURITY_DOMAIN));
            removeIfExists(client, elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
            removeIfExists(client, elytronAddress("security-domain", AS_ELYTRON_DOMAIN));
            removeIfExists(client, elytronAddress("constant-role-mapper", "PicketLinkOidcAsRoleMapper"));
            removeIfExists(client, elytronAddress("properties-realm", PROPERTIES_REALM));

            execute(client, addPropertiesRealm());
            execute(client, addRoleMapper());
            execute(client, addSecurityDomain());
            execute(client, addHttpAuth());
            execute(client, undertowAppSecurityDomain(AS_SECURITY_DOMAIN, HTTP_AUTH_FACTORY));
        }
    }

    public static void prepareServerHome(Path jbossHome) throws Exception {
        Path configDir = jbossHome.resolve("standalone/configuration");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("picketlink-users.properties"), "user1=password1\n");
        Files.writeString(configDir.resolve("picketlink-roles.properties"), "user1=role1\n");
        disableHttpsListener(configDir.resolve("standalone.xml"));
        Path keystoreTarget = configDir.resolve("jbid_test_keystore.jks");
        if (!Files.exists(keystoreTarget)) {
            try (InputStream keystore = DemoOidcElytronConfigurator.class.getResourceAsStream("/jbid_test_keystore.jks")) {
                if (keystore == null) {
                    throw new IllegalStateException("Missing test keystore /jbid_test_keystore.jks");
                }
                Files.copy(keystore, keystoreTarget);
            }
        }
    }

    private static void disableHttpsListener(Path standaloneXml) throws Exception {
        if (!Files.isRegularFile(standaloneXml)) {
            return;
        }
        String xml = Files.readString(standaloneXml);
        String patched = xml.replaceAll("\\s*<https-listener[^>]*/>\\s*", System.lineSeparator());
        if (!patched.equals(xml)) {
            Files.writeString(standaloneXml, patched);
        }
    }

    private static ModelNode addPropertiesRealm() {
        ModelNode add = operation("add", elytronAddress("properties-realm", PROPERTIES_REALM));
        add.get("users-properties").set(createPropertyExpression("picketlink-users.properties"));
        add.get("groups-properties").set(createPropertyExpression("picketlink-roles.properties"));
        return add;
    }

    private static ModelNode addRoleMapper() {
        ModelNode add = operation("add", elytronAddress("constant-role-mapper", "PicketLinkOidcAsRoleMapper"));
        add.get("roles").add("role1");
        return add;
    }

    private static ModelNode addSecurityDomain() {
        ModelNode add = operation("add", elytronAddress("security-domain", AS_ELYTRON_DOMAIN));
        add.get("realms").add().get("realm").set(PROPERTIES_REALM);
        add.get("default-realm").set(PROPERTIES_REALM);
        add.get("role-mapper").set("PicketLinkOidcAsRoleMapper");
        add.get("permission-mapper").set("default-permission-mapper");
        return add;
    }

    private static ModelNode addHttpAuth() {
        ModelNode add = operation("add", elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        add.get("security-domain").set(AS_ELYTRON_DOMAIN);
        add.get("http-server-mechanism-factory").set("global");
        add.get("mechanism-configurations").add().get("mechanism-name").set("FORM");
        add.get("mechanism-configurations").get(0).get("mechanism-realm-configurations").add()
                .get("realm-name").set(PROPERTIES_REALM);
        return add;
    }

    private static ModelNode undertowAppSecurityDomain(String domain, String httpAuthFactory) {
        ModelNode add = operation("add", undertowAppSecurityDomainAddress(domain));
        add.get("http-authentication-factory").set(httpAuthFactory);
        return add;
    }

    private static ModelNode createPropertyExpression(String fileName) {
        ModelNode expression = new ModelNode();
        expression.get("path").set(fileName);
        expression.get("relative-to").set("jboss.server.config.dir");
        if ("picketlink-users.properties".equals(fileName)) {
            expression.get("plain-text").set("true");
        }
        return expression;
    }

    private static ModelNode elytronAddress(String type, String name) {
        ModelNode address = new ModelNode();
        address.add("subsystem", "elytron");
        address.add(type, name);
        return address;
    }

    private static ModelNode undertowAppSecurityDomainAddress(String domain) {
        ModelNode address = new ModelNode();
        address.add("subsystem", "undertow");
        address.add("application-security-domain", domain);
        return address;
    }

    private static ModelNode operation(String name, ModelNode address) {
        ModelNode op = new ModelNode();
        op.get("operation").set(name);
        op.get("address").set(address);
        return op;
    }

    private static void execute(ModelControllerClient client, ModelNode operation) throws Exception {
        ModelNode response = client.execute(operation);
        if (!response.get("outcome").asString().equals("success")) {
            throw new IllegalStateException("Management operation failed: " + operation + " -> " + response);
        }
    }

    private static void removeIfExists(ModelControllerClient client, ModelNode address) throws Exception {
        ModelNode remove = operation("remove", address);
        ModelNode response = client.execute(remove);
        String outcome = response.get("outcome").asString();
        if (!outcome.equals("success") && !outcome.equals("failed")) {
            throw new IllegalStateException("Unexpected remove outcome: " + response);
        }
    }
}
