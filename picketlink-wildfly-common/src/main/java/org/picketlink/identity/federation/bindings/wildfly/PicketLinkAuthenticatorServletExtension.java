/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.identity.federation.bindings.wildfly;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.AuthMethodConfig;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.LoginConfig;
import java.util.List;

import javax.servlet.ServletContext;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see PicketLinkAuthenticator
 */
public class PicketLinkAuthenticatorServletExtension implements ServletExtension {

    static final String AUTH_METHOD_NAME = "SECURITY_DOMAIN";

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        LoginConfig loginConfig = deploymentInfo.getLoginConfig();

        if (loginConfig != null) {
            List<AuthMethodConfig> authMethods = loginConfig.getAuthMethods();

            if (authMethods != null) {
                for (AuthMethodConfig method : authMethods) {
                    if (method.getName().equals(AUTH_METHOD_NAME)) {
                        deploymentInfo.addAuthenticationMechanism(AUTH_METHOD_NAME, new PicketLinkAuthenticator.Factory(deploymentInfo.getIdentityManager()));
                    }
                }
            }
        }
    }
}
