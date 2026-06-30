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
public class SPInitiatedPostBindingIT {

    @Deployment(name = "idp", order = 1, testable = false)
    public static WebArchive deployIdp() {
        return SamlDeployments.idpWar();
    }

    @Deployment(name = "sp-post", order = 2, testable = false)
    public static WebArchive deploySp() {
        return SamlDeployments.spPostWar();
    }

    @Test
    public void testSpInitiatedPostBindingSso() throws Exception {
        SamlSsoTestSupport.assertSpInitiatedSamlSso("sp_post");
    }
}
