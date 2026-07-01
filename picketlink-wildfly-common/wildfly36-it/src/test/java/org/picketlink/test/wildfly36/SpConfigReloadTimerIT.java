package org.picketlink.test.wildfly36;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.test.wildfly36.deployment.SamlDeployments;
import org.picketlink.test.wildfly36.support.ConfigReloadTimerSetup;
import org.picketlink.test.wildfly36.support.ElytronTestSetup;

/**
 * Verifies {@code REFRESH_CONFIG_TIMER_INTERVAL} reloads handler-chain crypto policy on the Elytron SP path.
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup({ElytronTestSetup.class, ConfigReloadTimerSetup.class})
public class SpConfigReloadTimerIT {

    @Deployment(name = "idp-sig-legacy", order = 1, testable = false)
    public static WebArchive deployIdpLegacySigned() {
        return SamlDeployments.idpLegacySignedWar();
    }

    @Deployment(name = "sp-sig-reload", order = 2, testable = false)
    public static WebArchive deploySpReloadableConfig() {
        return SamlDeployments.spSignedReloadWar();
    }

    @Test
    public void testConfigReloadUpdatesLegacyCryptoPolicyOnElytronPath() throws Exception {
        SamlSsoTestSupport.assertSpInitiatedSamlSsoFails("sp-sig-reload");

        ConfigReloadTestSupport.writeSpSignedConfig(true);
        ConfigReloadTestSupport.waitForConfigReload();

        SamlSsoTestSupport.assertSpInitiatedSamlSso("sp-sig-reload");
    }
}
