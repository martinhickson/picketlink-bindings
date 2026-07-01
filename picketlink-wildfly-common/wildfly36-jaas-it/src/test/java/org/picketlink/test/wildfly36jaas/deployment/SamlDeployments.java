package org.picketlink.test.wildfly36jaas.deployment;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

public final class SamlDeployments {

    public static final String IDP_SECURITY_DOMAIN = "PicketLinkTestDomain";

    public static final String SP_SECURITY_DOMAIN = "PicketLinkSPDomain";

    /** @deprecated use {@link #IDP_SECURITY_DOMAIN} */
    public static final String SECURITY_DOMAIN = IDP_SECURITY_DOMAIN;

    private SamlDeployments() {
    }

    public static WebArchive idpWar() {
        return createWar("idp.war", "idp");
    }

    public static WebArchive spRedirectWar() {
        return createWar("sp.war", "sp");
    }

    public static WebArchive spPostWar() {
        return createWar("sp-post.war", "sp-post");
    }

    private static WebArchive createWar(String name, String resourceBase) {
        return ShrinkWrap.create(WebArchive.class, name)
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/web.xml"), "web.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/jboss-web.xml"), "jboss-web.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/picketlink.xml"), "picketlink.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/error.html"), "error.html")
                .addAsWebResource(SamlDeployments.class.getResource("/deployments/logout.html"), "logout.html")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/jboss-deployment-structure.xml"), "jboss-deployment-structure.xml")
                .addClass(FormLoginServlet.class)
                .addClass(SendUsernameServlet.class)
                .addClass(TestRoleGenerator.class);
    }
}
