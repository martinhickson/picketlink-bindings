package org.picketlink.test.wildfly36idm.deployment;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;

public final class IdmDeployments {

    private IdmDeployments() {
    }

    public static WebArchive idmWar() {
        return ShrinkWrap.create(WebArchive.class, "idm.war")
                .addAsWebInfResource(IdmDeployments.class.getResource("/deployments/idm/web.xml"), "web.xml")
                .addAsWebInfResource(IdmDeployments.class.getResource("/deployments/idm/jboss-web.xml"), "jboss-web.xml")
                .addAsWebInfResource(IdmDeployments.class.getResource("/deployments/idm/jboss-deployment-structure.xml"),
                        "jboss-deployment-structure.xml")
                .addAsWebInfResource(IdmDeployments.class.getResource("/deployments/idm/beans.xml"), "beans.xml")
                .addAsResource(IdmDeployments.class.getResource("/deployments/idm/persistence.xml"), "META-INF/persistence.xml")
                .addClass(WildFlyJpaContextInitializer.class)
                .addClass(IdmBootstrap.class)
                .addClass(IdmUserService.class)
                .addClass(IdmServlet.class);
    }
}
