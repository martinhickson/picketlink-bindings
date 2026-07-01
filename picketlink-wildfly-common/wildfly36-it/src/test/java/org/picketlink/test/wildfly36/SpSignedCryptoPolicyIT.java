package org.picketlink.test.wildfly36;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.test.wildfly36.deployment.SamlDeployments;
import org.picketlink.test.wildfly36.support.ElytronTestSetup;

/**
 * Elytron SP integration tests for signed SAML responses and crypto policy flags.
 */
@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup(ElytronTestSetup.class)
public class SpSignedCryptoPolicyIT {

    @Deployment(name = "idp-sig", order = 1, testable = false)
    public static WebArchive deployIdpSigned() {
        return SamlDeployments.idpSignedWar();
    }

    @Deployment(name = "idp-sig-legacy", order = 2, testable = false)
    public static WebArchive deployIdpLegacySigned() {
        return SamlDeployments.idpLegacySignedWar();
    }

    @Deployment(name = "sp-sig", order = 3, testable = false)
    public static WebArchive deploySpSigned() {
        return SamlDeployments.spSignedWar();
    }

    @Deployment(name = "sp-sig-legacy-reject", order = 4, testable = false)
    public static WebArchive deploySpLegacyReject() {
        return SamlDeployments.spLegacyRejectWar();
    }

    @Deployment(name = "sp-sig-legacy-accept", order = 5, testable = false)
    public static WebArchive deploySpLegacyAccept() {
        return SamlDeployments.spLegacyAcceptWar();
    }

    @Test
    public void testStrongSignedSsoSucceedsOnElytronPath() throws Exception {
        SamlSsoTestSupport.assertSpInitiatedSamlSso("sp-sig");
    }

    @Test
    public void testLegacySignedResponseRejectedByDefaultOnElytronPath() throws Exception {
        SamlSsoTestSupport.assertSpInitiatedSamlSsoFails("sp-sig-legacy-reject");
    }

    @Test
    public void testLegacySignedResponseAcceptedWhenConfiguredOnElytronPath() throws Exception {
        SamlSsoTestSupport.assertSpInitiatedSamlSso("sp-sig-legacy-accept");
    }
}
