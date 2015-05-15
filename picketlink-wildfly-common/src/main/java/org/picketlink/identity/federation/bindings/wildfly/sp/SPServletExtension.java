/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.IdentityURLProviderType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.picketlink.identity.federation.web.util.ConfigurationUtil.getConfiguration;

/**
 *
 * <p>{@link io.undertow.servlet.ServletExtension} that enables the SAML authentication mechanism for service provider deployments.</p>
 *
 * @author Pedro Igor
 */
public class SPServletExtension implements ServletExtension {

    private static final PicketLinkLogger LOGGER = PicketLinkLoggerFactory.getLogger();

    private final SAMLConfigurationProvider configurationProvider;
    private final PicketLinkAuditHelper auditHelper;

    public SPServletExtension(SAMLConfigurationProvider configurationProvider, PicketLinkAuditHelper auditHelper) {
        this.configurationProvider = configurationProvider;
        this.auditHelper = auditHelper;
    }

    public SPServletExtension() {
        this(null, null);
    }

    @Override
    public void handleDeployment(final DeploymentInfo deploymentInfo, final ServletContext servletContext) {
        LOGGER.debug("Processing PicketLink Extension [" + getClass() + "].");

        try {
            final PicketLinkType configuration;
            final SAMLConfigurationProvider configurationProvider = getConfigurationProvider(servletContext);

            if (configurationProvider != null) {
                configuration = configurationProvider.getPicketLinkConfiguration();
            } else {
                configuration = getConfiguration(servletContext);
            }

            if (configuration == null) {
                // we just ignore if the configuration was not found. This extension can be manually added by the subsystem,
                // in WildFly. In this case we don't have a configuration file inside deployments but the a configuration provided
                // by the subsystem's custom config provider.
                // Undertow subsystem will try to load this extension and that will cause an error if the config file is not inside
                // the deployment. So we just ignore and log a message.
                LOGGER.debug("No configuration found for deployment [" + deploymentInfo.getDeploymentName() + "].");
                return;
            }

            ProviderType providerType = configuration.getIdpOrSP();

            if (SPType.class.isInstance(providerType)) {
                LOGGER.debug("Configuring deployment [" + deploymentInfo.getDeploymentName() + "] as a SAML Service Provider.");

                deploymentInfo.addAuthenticationMechanism(HttpServletRequest.FORM_AUTH, new AuthenticationMechanismFactory() {
                    @Override
                    public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
                        try {
                            String loginPage = properties.get(LOGIN_PAGE);
                            String errorPage = properties.get(ERROR_PAGE);
                            PicketLinkAuditHelper auditHelper = getAuditHelper(configuration, servletContext);

                            if (configurationProvider != null) {
                                return new SPFormAuthenticationMechanism(formParserFactory, mechanismName, loginPage, errorPage, servletContext, configurationProvider, auditHelper);
                            }

                            return new SPFormAuthenticationMechanism(formParserFactory, mechanismName, loginPage, errorPage, servletContext, configuration, auditHelper);
                        } catch (ProcessingException e) {
                            throw new RuntimeException("Could not create SAML Authentication Mechanism for deployment [" + deploymentInfo.getDeploymentName() + "].", e);
                        }
                    }
                });

                SPType spType = (SPType) providerType;
                IdentityURLProviderType identityURLProvider = spType.getIdentityURLProvider();

                if (identityURLProvider != null) {
                    deploymentInfo.addOuterHandlerChainWrapper(IdentityURLProviderHandler.wrapper(spType, servletContext));
                }
            }
        } catch (ProcessingException e) {
            throw new RuntimeException("Error configuring PicketLink SAML extension [" + getClass() + "] to deployment [" + deploymentInfo.getDeploymentName()  + "].", e);
        } catch (ConfigurationException e) {
            throw new RuntimeException("Could not load PicketLink configuration for deployment [" + deploymentInfo.getDeploymentName()  + "].", e);
        }
    }

    private SAMLConfigurationProvider getConfigurationProvider(ServletContext servletContext) {
        if (this.configurationProvider == null) {
            return ConfigurationUtil.getConfigurationProvider(servletContext);
        }

        return this.configurationProvider;
    }

    private PicketLinkAuditHelper getAuditHelper(PicketLinkType configuration, ServletContext servletContext) {
        if (configuration.isEnableAudit() && this.auditHelper == null) {
            return ConfigurationUtil.getAuditHelper(servletContext);
        }

        return this.auditHelper;
    }
}
