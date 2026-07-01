package org.picketlink.test.wildfly36.deployment;

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

    public static WebArchive idpMetadataWar() {
        return createMetadataWar("idp-metadata.war", "idp-metadata", true);
    }

    public static WebArchive idpGeneratedMetadataWar() {
        return createMetadataWar("idp-metadata-generated.war", "idp-metadata-generated", true, false);
    }

    public static WebArchive spMetadataWar() {
        return createMetadataWar("sp-metadata.war", "sp-metadata", false);
    }

    public static WebArchive spGeneratedMetadataWar() {
        return createMetadataWar("sp-metadata-generated.war", "sp-metadata-generated", false, false);
    }

    private static WebArchive createMetadataWar(String name, String resourceBase, boolean idp) {
        return createMetadataWar(name, resourceBase, idp, true);
    }

    private static WebArchive createMetadataWar(String name, String resourceBase, boolean idp, boolean includeStaticMetadata) {
        WebArchive archive = ShrinkWrap.create(WebArchive.class, name)
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/web.xml"), "web.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/jboss-web.xml"), "jboss-web.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/metadata-config.xml"), "metadata-config.xml")
                .addAsWebInfResource(SamlDeployments.class.getResource("/deployments/jboss-deployment-structure.xml"), "jboss-deployment-structure.xml");
        if (idp) {
            if (includeStaticMetadata) {
                archive.addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/idp-metadata.xml"), "idp-metadata.xml");
            }
            archive.addClass(TestRoleGenerator.class);
        } else if (includeStaticMetadata) {
            archive.addAsWebInfResource(SamlDeployments.class.getResource("/deployments/" + resourceBase + "/sp-metadata.xml"), "sp-metadata.xml");
        }
        return archive;
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
