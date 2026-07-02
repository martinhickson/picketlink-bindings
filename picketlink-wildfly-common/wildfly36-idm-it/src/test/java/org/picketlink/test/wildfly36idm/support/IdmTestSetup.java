package org.picketlink.test.wildfly36idm.support;

import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;

/**
 * Placeholder server setup for IDM ITs. JPA uses WildFly's built-in {@code ExampleDS}.
 */
public class IdmTestSetup implements ServerSetupTask {

    @Override
    public void setup(ManagementClient managementClient, String containerId) {
        // ExampleDS is present in the default standalone configuration.
    }

    @Override
    public void tearDown(ManagementClient managementClient, String containerId) {
    }
}
