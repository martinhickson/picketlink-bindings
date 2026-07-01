package org.picketlink.test.wildfly36.support;

import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.picketlink.test.wildfly36.ConfigReloadTestSupport;

/**
 * Writes the initial reloadable SP config file before deployments start.
 */
public class ConfigReloadTimerSetup implements ServerSetupTask {

    @Override
    public void setup(ManagementClient managementClient, String containerId) throws Exception {
        ConfigReloadTestSupport.writeSpSignedConfig(false);
    }

    @Override
    public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
    }
}
