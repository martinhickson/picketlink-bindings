package org.picketlink.test.wildfly36jaas;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.test.wildfly36jaas.deployment.SamlDeployments;
import org.picketlink.test.wildfly36jaas.support.ElytronTestSetup;

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

    @Test
    public void testSpLocalLogoutAfterPostBindingSso() throws Exception {
        SamlSsoTestSupport.assertSpLocalLogout("sp_post");
    }

    @Test
    public void testSpGlobalLogoutAfterPostBindingSso() throws Exception {
        SamlSsoTestSupport.assertSpGlobalLogout("sp_post");
    }
}
