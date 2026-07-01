package org.picketlink.test.wildfly36.support;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.dmr.ModelNode;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlSecurityRealm;
import org.picketlink.test.wildfly36.deployment.SamlDeployments;
import org.picketlink.test.wildfly36.support.PicketLinkModuleInstaller;

public class ElytronTestSetup implements ServerSetupTask {

    private static final String PROPERTIES_REALM = "PicketLinkTestRealm";
    private static final String SAML_REALM = "PicketLinkSamlRealm";
    private static final String SAML_REALM_MAPPER = "picketlink-saml-realm-mapper";
    private static final String HTTP_AUTH_FACTORY = "PicketLinkTestHttpAuth";
    private static final String SP_HTTP_AUTH_FACTORY = "PicketLinkSPHttpAuth";
    private static final String IDP_SECURITY_DOMAIN = SamlDeployments.IDP_SECURITY_DOMAIN;
    private static final String SP_SECURITY_DOMAIN = SamlDeployments.SP_SECURITY_DOMAIN;
    private static final String IDP_ELYTRON_DOMAIN = "PicketLinkTestElytronDomain";
    private static final String PICKETLINK_MECHANISM_FACTORY = "picketlink-saml-mechanism-factory";
    private static final String AGGREGATE_MECHANISM_FACTORY = "picketlink-http-mechanism-factory";
    private static final String PICKETLINK_MODULE = PicketLinkModuleInstaller.MODULE_NAME;

    private static final String USERS_FILE = "picketlink-users.properties";
    private static final String ROLES_FILE = "picketlink-roles.properties";
    private static final String SP_JAAS_CONFIG = "picketlink-sp.login.conf";
    private static final String SP_JAAS_ENTRY = "PicketLinkSP";

    @Override
    public void setup(ManagementClient managementClient, String containerId) throws Exception {
        writeCredentialFiles();
        writeSpJaasConfig();
        ModelControllerClient client = managementClient.getControllerClient();

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

        ModelNode addPropertiesRealm = operation("add", elytronAddress("properties-realm", PROPERTIES_REALM));
        addPropertiesRealm.get("users-properties").set(createPropertyExpression(USERS_FILE));
        addPropertiesRealm.get("groups-properties").set(createPropertyExpression(ROLES_FILE));
        execute(client, addPropertiesRealm);

        ModelNode addSamlRealm = operation("add", elytronAddress("custom-realm", SAML_REALM));
        addSamlRealm.get("class-name").set(PicketLinkSamlSecurityRealm.class.getName());
        addSamlRealm.get("module").set(PICKETLINK_MODULE);
        execute(client, addSamlRealm);

        ModelNode addRealmMapper = operation("add", elytronAddress("constant-realm-mapper", SAML_REALM_MAPPER));
        addRealmMapper.get("realm-name").set(SAML_REALM);
        execute(client, addRealmMapper);

        ModelNode addTestRoleMapper = operation("add", elytronAddress("constant-role-mapper", "PicketLinkTestRoleMapper"));
        addTestRoleMapper.get("roles").add("role1");
        execute(client, addTestRoleMapper);

        ModelNode addMechanismFactory = operation("add",
                elytronAddress("service-loader-http-server-mechanism-factory", PICKETLINK_MECHANISM_FACTORY));
        addMechanismFactory.get("module").set(PICKETLINK_MODULE);
        execute(client, addMechanismFactory);

        ModelNode addAggregateMechanismFactory = operation("add",
                elytronAddress("aggregate-http-server-mechanism-factory", AGGREGATE_MECHANISM_FACTORY));
        addAggregateMechanismFactory.get("http-server-mechanism-factories").add(PICKETLINK_MECHANISM_FACTORY);
        addAggregateMechanismFactory.get("http-server-mechanism-factories").add("global");
        execute(client, addAggregateMechanismFactory);

        ModelNode addSecurityDomain = operation("add", elytronAddress("security-domain", IDP_ELYTRON_DOMAIN));
        ModelNode propertiesRealmMapping = addSecurityDomain.get("realms").add();
        propertiesRealmMapping.get("realm").set(PROPERTIES_REALM);
        ModelNode samlRealmMapping = addSecurityDomain.get("realms").add();
        samlRealmMapping.get("realm").set(SAML_REALM);
        addSecurityDomain.get("default-realm").set(PROPERTIES_REALM);
        addSecurityDomain.get("role-mapper").set("PicketLinkTestRoleMapper");
        addSecurityDomain.get("permission-mapper").set("default-permission-mapper");
        execute(client, addSecurityDomain);

        ModelNode addHttpAuth = operation("add", elytronAddress("http-authentication-factory", HTTP_AUTH_FACTORY));
        addHttpAuth.get("security-domain").set(IDP_ELYTRON_DOMAIN);
        addHttpAuth.get("http-server-mechanism-factory").set("global");
        ModelNode formMechanism = addHttpAuth.get("mechanism-configurations").add();
        formMechanism.get("mechanism-name").set("FORM");
        ModelNode formMechanismRealm = formMechanism.get("mechanism-realm-configurations").add();
        formMechanismRealm.get("realm-name").set(PROPERTIES_REALM);
        execute(client, addHttpAuth);

        ModelNode addSpHttpAuth = operation("add", elytronAddress("http-authentication-factory", SP_HTTP_AUTH_FACTORY));
        addSpHttpAuth.get("security-domain").set(IDP_ELYTRON_DOMAIN);
        addSpHttpAuth.get("http-server-mechanism-factory").set(AGGREGATE_MECHANISM_FACTORY);
        ModelNode picketlinkMechanism = addSpHttpAuth.get("mechanism-configurations").add();
        picketlinkMechanism.get("mechanism-name").set("PICKETLINK-SAML");
        ModelNode picketlinkMechanismRealm = picketlinkMechanism.get("mechanism-realm-configurations").add();
        picketlinkMechanismRealm.get("realm-name").set(SAML_REALM);
        picketlinkMechanismRealm.get("realm-mapper").set(SAML_REALM_MAPPER);
        execute(client, addSpHttpAuth);

        ModelNode addIdpAppSecurityDomain = undertowAppSecurityDomain(IDP_SECURITY_DOMAIN);
        addIdpAppSecurityDomain.get("http-authentication-factory").set(HTTP_AUTH_FACTORY);
        execute(client, addIdpAppSecurityDomain);

        ModelNode addSpAppSecurityDomain = undertowAppSecurityDomain(SP_SECURITY_DOMAIN);
        addSpAppSecurityDomain.get("http-authentication-factory").set(SP_HTTP_AUTH_FACTORY);
        execute(client, addSpAppSecurityDomain);
    }

    @Override
    public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
        ModelControllerClient client = managementClient.getControllerClient();
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

    private static void writeSpJaasConfig() throws Exception {
        String jbossHome = System.getProperty("jboss.home");
        if (jbossHome == null || jbossHome.isBlank()) {
            throw new IllegalStateException("jboss.home system property is not set");
        }

        Path configDir = Paths.get(jbossHome, "standalone", "configuration");
        Files.createDirectories(configDir);
        String jaasConfig = SP_JAAS_ENTRY + " {\n"
                + "    org.picketlink.identity.federation.bindings.wildfly.SAML2LoginModule required;\n"
                + "};\n";
        Files.writeString(configDir.resolve(SP_JAAS_CONFIG), jaasConfig);
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
