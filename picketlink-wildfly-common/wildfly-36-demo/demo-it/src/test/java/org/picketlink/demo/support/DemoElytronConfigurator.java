package org.picketlink.demo.support;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.dmr.ModelNode;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlSecurityRealm;

public final class DemoElytronConfigurator {

    private static final String PROPERTIES_REALM = "PicketLinkTestRealm";
    private static final String SAML_REALM = "PicketLinkSamlRealm";
    private static final String SAML_REALM_MAPPER = "picketlink-saml-realm-mapper";
    private static final String HTTP_AUTH_FACTORY = "PicketLinkTestHttpAuth";
    private static final String SP_HTTP_AUTH_FACTORY = "PicketLinkSPHttpAuth";
    private static final String IDP_SECURITY_DOMAIN = "PicketLinkTestDomain";
    private static final String SP_SECURITY_DOMAIN = "PicketLinkSPDomain";
    private static final String IDP_ELYTRON_DOMAIN = "PicketLinkTestElytronDomain";
    private static final String PICKETLINK_MECHANISM_FACTORY = "picketlink-saml-mechanism-factory";
    private static final String AGGREGATE_MECHANISM_FACTORY = "picketlink-http-mechanism-factory";
    private static final String PICKETLINK_MODULE = PicketLinkModuleInstaller.MODULE_NAME;

    private DemoElytronConfigurator() {
    }

    public static void configure(WildFlyServer server) throws Exception {
        prepareServerHome(server.jbossHome());
        try (ModelControllerClient client = ModelControllerClient.Factory.create(
                java.net.InetAddress.getByName(server.bindAddress()), DemoEnvironment.MGMT_PORT)) {
            removeIfExists(client, undertowAppSecurityDomainAddress(SP_SECURITY_DOMAIN));
            removeIfExists(client, undertowAppSecurityDomainAddress(IDP_SECURITY_DOMAIN));
            removeIfExists(client, elytronAddress("http-authentication-factory", SP_HTTP_AUTH_FACTORY));
            removeIfExists(client, elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
            removeIfExists(client, elytronAddress("security-domain", IDP_ELYTRON_DOMAIN));
            removeIfExists(client, elytronAddress("aggregate-http-server-mechanism-factory", AGGREGATE_MECHANISM_FACTORY));
            removeIfExists(client, elytronAddress("service-loader-http-server-mechanism-factory", PICKETLINK_MECHANISM_FACTORY));
            removeIfExists(client, elytronAddress("constant-role-mapper", "PicketLinkTestRoleMapper"));
            removeIfExists(client, elytronAddress("constant-realm-mapper", SAML_REALM_MAPPER));
            removeIfExists(client, elytronAddress("custom-realm", SAML_REALM));
            removeIfExists(client, elytronAddress("properties-realm", PROPERTIES_REALM));

            execute(client, addPropertiesRealm());
            execute(client, addSamlRealm());
            execute(client, addRealmMapper());
            execute(client, addTestRoleMapper());
            execute(client, addMechanismFactory());
            execute(client, addAggregateMechanismFactory());
            execute(client, addSecurityDomain());
            execute(client, addHttpAuth());
            execute(client, addSpHttpAuth());
            execute(client, undertowAppSecurityDomain(IDP_SECURITY_DOMAIN, HTTP_AUTH_FACTORY));
            execute(client, undertowAppSecurityDomain(SP_SECURITY_DOMAIN, SP_HTTP_AUTH_FACTORY));
        }
    }

    public static void prepareServerHome(Path jbossHome) throws Exception {
        writeCredentialFiles(jbossHome);
    }

    private static void writeCredentialFiles(Path jbossHome) throws Exception {
        Path configDir = jbossHome.resolve("standalone/configuration");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("picketlink-users.properties"), "user1=password1\n");
        Files.writeString(configDir.resolve("picketlink-roles.properties"), "user1=role1\n");
        Files.writeString(configDir.resolve("picketlink-sp.login.conf"),
                "PicketLinkSP {\n    org.picketlink.identity.federation.bindings.wildfly.SAML2LoginModule required;\n};\n");
        Path keystoreTarget = configDir.resolve("jbid_test_keystore.jks");
        if (!Files.exists(keystoreTarget)) {
            try (InputStream keystore = DemoElytronConfigurator.class.getResourceAsStream("/jbid_test_keystore.jks")) {
                if (keystore == null) {
                    throw new IllegalStateException("Missing test keystore /jbid_test_keystore.jks");
                }
                Files.copy(keystore, keystoreTarget);
            }
        }
    }

    private static ModelNode addPropertiesRealm() {
        ModelNode add = operation("add", elytronAddress("properties-realm", PROPERTIES_REALM));
        add.get("users-properties").set(createPropertyExpression("picketlink-users.properties"));
        add.get("groups-properties").set(createPropertyExpression("picketlink-roles.properties"));
        return add;
    }

    private static ModelNode addSamlRealm() {
        ModelNode add = operation("add", elytronAddress("custom-realm", SAML_REALM));
        add.get("class-name").set(PicketLinkSamlSecurityRealm.class.getName());
        add.get("module").set(PICKETLINK_MODULE);
        return add;
    }

    private static ModelNode addRealmMapper() {
        ModelNode add = operation("add", elytronAddress("constant-realm-mapper", SAML_REALM_MAPPER));
        add.get("realm-name").set(SAML_REALM);
        return add;
    }

    private static ModelNode addTestRoleMapper() {
        ModelNode add = operation("add", elytronAddress("constant-role-mapper", "PicketLinkTestRoleMapper"));
        add.get("roles").add("role1");
        return add;
    }

    private static ModelNode addMechanismFactory() {
        ModelNode add = operation("add", elytronAddress("service-loader-http-server-mechanism-factory", PICKETLINK_MECHANISM_FACTORY));
        add.get("module").set(PICKETLINK_MODULE);
        return add;
    }

    private static ModelNode addAggregateMechanismFactory() {
        ModelNode add = operation("add", elytronAddress("aggregate-http-server-mechanism-factory", AGGREGATE_MECHANISM_FACTORY));
        add.get("http-server-mechanism-factories").add(PICKETLINK_MECHANISM_FACTORY);
        add.get("http-server-mechanism-factories").add("global");
        return add;
    }

    private static ModelNode addSecurityDomain() {
        ModelNode add = operation("add", elytronAddress("security-domain", IDP_ELYTRON_DOMAIN));
        add.get("realms").add().get("realm").set(PROPERTIES_REALM);
        add.get("realms").add().get("realm").set(SAML_REALM);
        add.get("default-realm").set(PROPERTIES_REALM);
        add.get("role-mapper").set("PicketLinkTestRoleMapper");
        add.get("permission-mapper").set("default-permission-mapper");
        return add;
    }

    private static ModelNode addHttpAuth() {
        ModelNode add = operation("add", elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        add.get("security-domain").set(IDP_ELYTRON_DOMAIN);
        add.get("http-server-mechanism-factory").set("global");
        ModelNode form = add.get("mechanism-configurations").add();
        form.get("mechanism-name").set("FORM");
        form.get("mechanism-realm-configurations").add().get("realm-name").set(PROPERTIES_REALM);
        return add;
    }

    private static ModelNode addSpHttpAuth() {
        ModelNode add = operation("add", elytronAddress("http-authentication-factory", SP_HTTP_AUTH_FACTORY));
        add.get("security-domain").set(IDP_ELYTRON_DOMAIN);
        add.get("http-server-mechanism-factory").set(AGGREGATE_MECHANISM_FACTORY);
        ModelNode saml = add.get("mechanism-configurations").add();
        saml.get("mechanism-name").set("PICKETLINK-SAML");
        ModelNode realm = saml.get("mechanism-realm-configurations").add();
        realm.get("realm-name").set(SAML_REALM);
        realm.get("realm-mapper").set(SAML_REALM_MAPPER);
        return add;
    }

    private static ModelNode undertowAppSecurityDomain(String name, String httpAuthFactory) {
        ModelNode add = operation("add", undertowAppSecurityDomainAddress(name));
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
        client.execute(operation("remove", address));
    }

    private static void execute(ModelControllerClient client, ModelNode operation) throws Exception {
        ModelNode response = client.execute(operation);
        if (!"success".equals(response.get("outcome").asString())) {
            throw new IllegalStateException("Management operation failed: " + operation + " => " + response);
        }
    }
}
