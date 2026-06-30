package org.picketlink.test.wildfly36.support;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.dmr.ModelNode;
import org.picketlink.test.wildfly36.deployment.SamlDeployments;

public class ElytronTestSetup implements ServerSetupTask {

    private static final String REALM = "PicketLinkTestRealm";
    private static final String HTTP_AUTH_FACTORY = "PicketLinkTestHttpAuth";
    private static final String SECURITY_DOMAIN = SamlDeployments.IDP_SECURITY_DOMAIN;
    private static final String USERS_FILE = "picketlink-users.properties";
    private static final String ROLES_FILE = "picketlink-roles.properties";

    @Override
    public void setup(ManagementClient managementClient, String containerId) throws Exception {
        writeCredentialFiles();
        ModelControllerClient client = managementClient.getControllerClient();

        removeIfExists(client, undertowAppSecurityDomainAddress(SECURITY_DOMAIN));
        removeIfExists(client, elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        removeIfExists(client, elytronAddress("security-domain", SECURITY_DOMAIN));
        removeIfExists(client, elytronAddress("properties-realm", REALM));

        ModelNode addRealm = operation("add", elytronAddress("properties-realm", REALM));
        addRealm.get("users-properties").set(createPropertyExpression(USERS_FILE));
        addRealm.get("groups-properties").set(createPropertyExpression(ROLES_FILE));
        execute(client, addRealm);

        ModelNode addSecurityDomain = operation("add", elytronAddress("security-domain", SECURITY_DOMAIN));
        ModelNode realmMapping = addSecurityDomain.get("realms").add();
        realmMapping.get("realm").set(REALM);
        addSecurityDomain.get("default-realm").set(REALM);
        addSecurityDomain.get("permission-mapper").set("default-permission-mapper");
        execute(client, addSecurityDomain);

        ModelNode addHttpAuth = operation("add", elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        addHttpAuth.get("security-domain").set(SECURITY_DOMAIN);
        addHttpAuth.get("http-server-mechanism-factory").set("global");
        ModelNode mechanismConfig = addHttpAuth.get("mechanism-configurations").add();
        mechanismConfig.get("mechanism-name").set("FORM");
        ModelNode mechanismRealm = mechanismConfig.get("mechanism-realm-configurations").add();
        mechanismRealm.get("realm-name").set(REALM);
        execute(client, addHttpAuth);

        ModelNode addAppSecurityDomain = undertowAppSecurityDomain(SECURITY_DOMAIN);
        addAppSecurityDomain.get("http-authentication-factory").set(HTTP_AUTH_FACTORY);
        execute(client, addAppSecurityDomain);
    }

    @Override
    public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
        ModelControllerClient client = managementClient.getControllerClient();
        removeIfExists(client, undertowAppSecurityDomainAddress(SECURITY_DOMAIN));
        removeIfExists(client, elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        removeIfExists(client, elytronAddress("security-domain", SECURITY_DOMAIN));
        removeIfExists(client, elytronAddress("properties-realm", REALM));
    }

    private static void writeCredentialFiles() throws Exception {
        String jbossHome = System.getProperty("jboss.home");
        if (jbossHome == null || jbossHome.isBlank()) {
            throw new IllegalStateException("jboss.home system property is not set");
        }

        Path configDir = Paths.get(jbossHome, "standalone", "configuration");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve(USERS_FILE), "user1=password1\n");
        Files.writeString(configDir.resolve(ROLES_FILE), "user1=role1\n");
    }

    private static ModelNode createPropertyExpression(String fileName) {
        ModelNode expression = new ModelNode();
        expression.get("path").set(fileName);
        expression.get("relative-to").set("jboss.server.config.dir");
        if (USERS_FILE.equals(fileName)) {
            expression.get("plain-text").set("true");
        }
        return expression;
    }

    private static ModelNode undertowAppSecurityDomain(String name) {
        ModelNode addAppSecurityDomain = new ModelNode();
        addAppSecurityDomain.get("address").set(undertowAppSecurityDomainAddress(name));
        addAppSecurityDomain.get("operation").set("add");
        return addAppSecurityDomain;
    }

    private static ModelNode undertowAppSecurityDomainAddress(String name) {
        return new ModelNode().add("subsystem", "undertow").add("application-security-domain", name);
    }

    private static ModelNode elytronAddress(String type, String name) {
        ModelNode address = new ModelNode();
        address.add("subsystem", "elytron").add(type, name);
        return address;
    }

    private static ModelNode operation(String name, ModelNode address) {
        ModelNode operation = new ModelNode();
        operation.get("address").set(address);
        operation.get("operation").set(name);
        return operation;
    }

    private static void removeIfExists(ModelControllerClient client, ModelNode address) throws Exception {
        ModelNode remove = operation("remove", address);
        client.execute(remove);
    }

    private static void execute(ModelControllerClient client, ModelNode operation) throws Exception {
        ModelNode response = client.execute(operation);
        if (!"success".equals(response.get("outcome").asString())) {
            throw new IllegalStateException("Management operation failed: " + operation + " => " + response);
        }
    }
}
