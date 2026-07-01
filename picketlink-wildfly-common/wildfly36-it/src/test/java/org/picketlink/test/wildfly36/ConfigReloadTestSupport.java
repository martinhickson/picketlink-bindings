package org.picketlink.test.wildfly36;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.picketlink.test.wildfly36.deployment.FileReloadableSAMLConfigurationProvider;

public final class ConfigReloadTestSupport {

    private ConfigReloadTestSupport() {
    }

    public static Path configFilePath() {
        String configuredPath = System.getProperty(FileReloadableSAMLConfigurationProvider.CONFIG_PATH_PROPERTY);
        if (configuredPath != null && !configuredPath.isBlank()) {
            return Paths.get(configuredPath);
        }
        String jbossHome = System.getProperty("jboss.home");
        if (jbossHome != null && !jbossHome.isBlank()) {
            return Paths.get(jbossHome, "standalone", "configuration", "picketlink-reload-test.xml");
        }
        throw new IllegalStateException("Cannot resolve reloadable PicketLink config file path");
    }

    public static void writeSpSignedConfig(boolean acceptLegacyAlgorithms) throws Exception {
        int port = Integer.getInteger("test.http.port", 8180);
        String keystorePath = System.getProperty("picketlink.test.keystore.path");
        if (keystorePath == null || keystorePath.isBlank()) {
            throw new IllegalStateException("picketlink.test.keystore.path system property is not set");
        }

        String acceptLegacyAttribute = acceptLegacyAlgorithms ? " AcceptLegacyAlgorithms=\"true\"" : "";
        String xml = "<PicketLink xmlns=\"urn:picketlink:identity-federation:config:2.1\">"
                + "<PicketLinkSP xmlns=\"urn:picketlink:identity-federation:config:2.1\""
                + " SupportsSignatures=\"true\"" + acceptLegacyAttribute
                + " BindingType=\"REDIRECT\" RelayState=\"someURL\" LogOutPage=\"/logout.html\">"
                + "<IdentityURL>http://localhost:" + port + "/idp-sig-legacy/</IdentityURL>"
                + "<ServiceURL>http://localhost:" + port + "/sp-sig-reload/</ServiceURL>"
                + "<KeyProvider ClassName=\"org.picketlink.identity.federation.core.impl.KeyStoreKeyManager\">"
                + "<Auth Key=\"KeyStoreURL\" Value=\"" + keystorePath + "\"/>"
                + "<Auth Key=\"KeyStorePass\" Value=\"store123\"/>"
                + "<Auth Key=\"SigningKeyPass\" Value=\"test123\"/>"
                + "<Auth Key=\"SigningKeyAlias\" Value=\"servercert\"/>"
                + "<ValidatingAlias Key=\"localhost\" Value=\"servercert\"/>"
                + "<SigningAlias>servercert</SigningAlias>"
                + "</KeyProvider>"
                + "</PicketLinkSP>"
                + "<Handlers xmlns=\"urn:picketlink:identity-federation:handler:config:2.1\">"
                + "<Handler class=\"org.picketlink.identity.federation.web.handlers.saml2.SAML2LogOutHandler\"/>"
                + "<Handler class=\"org.picketlink.identity.federation.web.handlers.saml2.SAML2SignatureValidationHandler\"/>"
                + "<Handler class=\"org.picketlink.identity.federation.web.handlers.saml2.SAML2AuthenticationHandler\"/>"
                + "<Handler class=\"org.picketlink.identity.federation.web.handlers.saml2.RolesGenerationHandler\"/>"
                + "</Handlers>"
                + "</PicketLink>";

        Path configFile = configFilePath();
        Files.createDirectories(configFile.getParent());
        Files.writeString(configFile, xml);
    }

    public static void waitForConfigReload() throws InterruptedException {
        long timerIntervalMs = Long.getLong("picketlink.test.reload.timer.interval.ms", 500L);
        Thread.sleep(timerIntervalMs * 3);
    }
}
