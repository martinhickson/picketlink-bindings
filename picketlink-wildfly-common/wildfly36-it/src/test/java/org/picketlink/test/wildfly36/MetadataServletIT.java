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

@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup(ElytronTestSetup.class)
public class MetadataServletIT {

    @Deployment(name = "idp-metadata", order = 1, testable = false)
    public static WebArchive deployIdpMetadata() {
        return SamlDeployments.idpMetadataWar();
    }

    @Deployment(name = "sp-metadata", order = 2, testable = false)
    public static WebArchive deploySpMetadata() {
        return SamlDeployments.spMetadataWar();
    }

    @Test
    public void testIdpMetadataServlet() throws Exception {
        MetadataTestSupport.assertIdpMetadataEndpoint();
    }

    @Test
    public void testSpMetadataServletSp() throws Exception {
        MetadataTestSupport.assertSpMetadataEndpoint();
    }

    @Deployment(name = "sp-metadata-generated", order = 3, testable = false)
    public static WebArchive deploySpGeneratedMetadata() {
        return SamlDeployments.spGeneratedMetadataWar();
    }

    @Test
    public void testSpMetadataServletSpGenerated() throws Exception {
        MetadataTestSupport.assertSpGeneratedMetadataEndpoint();
    }

    @Deployment(name = "idp-metadata-generated", order = 4, testable = false)
    public static WebArchive deployIdpGeneratedMetadata() {
        return SamlDeployments.idpGeneratedMetadataWar();
    }

    @Test
    public void testIdpMetadataServletGenerated() throws Exception {
        MetadataTestSupport.assertIdpGeneratedMetadataEndpoint();
    }
}
