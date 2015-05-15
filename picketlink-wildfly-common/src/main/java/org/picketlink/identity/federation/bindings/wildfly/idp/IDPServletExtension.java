/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.picketlink.identity.federation.bindings.wildfly.idp;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.FilterInfo;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.core.impl.EmptyAttributeManager;
import org.picketlink.identity.federation.web.filters.IDPFilter;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;

import javax.servlet.DispatcherType;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.picketlink.common.constants.GeneralConstants.AUDIT_HELPER;
import static org.picketlink.common.constants.GeneralConstants.CONFIGURATION;
import static org.picketlink.common.constants.GeneralConstants.CONFIG_PROVIDER;

/**
 * An implementation of {@link ServletExtension} that can turn a deployment
 * into an IDP
 *
 * @author Anil Saldhana
 * @since November 25, 2013
 */
public class IDPServletExtension implements ServletExtension{

    private static final PicketLinkLogger LOGGER = PicketLinkLoggerFactory.getLogger();

    private final SAMLConfigurationProvider configurationProvider;
    private final PicketLinkAuditHelper auditHelper;

    public IDPServletExtension(SAMLConfigurationProvider configurationProvider, PicketLinkAuditHelper auditHelper) {
        this.configurationProvider = configurationProvider;
        this.auditHelper = auditHelper;
    }

    public IDPServletExtension() {
        this(null, null);
    }

    @Override
    public void handleDeployment(final DeploymentInfo deploymentInfo, final ServletContext servletContext) {
        LOGGER.debug("Processing PicketLink Extension [" + getClass() + "].");

        try {
            final PicketLinkType picketLinkConfiguration = getConfiguration(servletContext);

            if (picketLinkConfiguration == null) {
                // we just ignore if the configuration was not found. This extension can be manually added by the subsystem,
                // in WildFly. In this case we don't have a configuration file inside deployments but the a configuration provided
                // by the subsystem's custom config provider.
                // Undertow subsystem will try to load this extension and that will cause an error if the config file is not inside
                // the deployment. So we just ignore and log a message.
                LOGGER.debug("No configuration found for deployment [" + deploymentInfo.getDeploymentName() + "].");
                return;
            }

            ProviderType providerType = picketLinkConfiguration.getIdpOrSP();

            if (IDPType.class.isInstance(providerType)) {
                LOGGER.debug("Configuring deployment [" + deploymentInfo.getDeploymentName() + "] as a SAML Identity Provider.");

                deploymentInfo.addAuthenticationMechanism(HttpServletRequest.FORM_AUTH, new AuthenticationMechanismFactory() {
                    @Override
                    public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
                        String loginPage = properties.get(LOGIN_PAGE);
                        String errorPage = properties.get(ERROR_PAGE);
                        PicketLinkAuditHelper auditHelper = getAuditHelper(picketLinkConfiguration, servletContext);

                        return new IDPAuthenticationMechanism(formParserFactory, mechanismName, loginPage, errorPage, picketLinkConfiguration, auditHelper);
                    }
                });

                IDPType idpType = (IDPType) providerType;

                if (!idpType.hasAttributeManager()) {
                    idpType.setAttributeManager(EmptyAttributeManager.class.getName());
                }

                if (!idpType.hasRoleGenerator()) {
                    idpType.setRoleGenerator(UndertowRoleGenerator.class.getName());
                }

                // we set the config provider and audit helper to the application scope so we can retrive them from the filter during the initialization
                servletContext.setAttribute(CONFIGURATION, picketLinkConfiguration);
                servletContext.setAttribute(CONFIG_PROVIDER, this.configurationProvider);
                servletContext.setAttribute(AUDIT_HELPER, this.auditHelper);

                configureFilterIfNecessary(deploymentInfo);
            }
        } catch (ProcessingException e) {
            throw new RuntimeException("Error configuring PicketLink SAML extension [" + getClass() + "] to deployment [" + deploymentInfo.getDeploymentName()  + "].", e);
        } catch (ConfigurationException e) {
            throw new RuntimeException("Could not load PicketLink configuration for deployment [" + deploymentInfo.getDeploymentName()  + "].", e);
        }
    }

    private PicketLinkType getConfiguration(ServletContext servletContext) throws ProcessingException, ConfigurationException {
        final SAMLConfigurationProvider configurationProvider = getConfigurationProvider(servletContext);

        if (configurationProvider != null) {
            return configurationProvider.getPicketLinkConfiguration();
        }

        return ConfigurationUtil.getConfiguration(servletContext);
    }

    private void configureFilterIfNecessary(DeploymentInfo deploymentInfo) {
        if (!hasFilter(deploymentInfo)) {
            LOGGER.debug("Enabling SAML IDPFilter for deployment [" + deploymentInfo.getDeploymentName() + "].");
            String filterName = IDPFilter.class.getSimpleName();

            deploymentInfo.addFilter(new FilterInfo(filterName, IDPFilter.class));
            deploymentInfo.addFilterUrlMapping(filterName, "/*", DispatcherType.REQUEST);
        }
    }

    private boolean hasFilter(DeploymentInfo deploymentInfo) {
        Map<String, FilterInfo> filters = deploymentInfo.getFilters();

        for (FilterInfo filterInfo : filters.values()) {
            if (IDPFilter.class.isAssignableFrom(filterInfo.getFilterClass())) {
                return true;
            }
        }

        return false;
    }

    private SAMLConfigurationProvider getConfigurationProvider(ServletContext servletContext) {
        if (this.configurationProvider == null) {
            return ConfigurationUtil.getConfigurationProvider(servletContext);
        }

        return this.configurationProvider;
    }

    private PicketLinkAuditHelper getAuditHelper(PicketLinkType picketLinkConfiguration, ServletContext servletContext) {
        if (picketLinkConfiguration.isEnableAudit() && this.auditHelper == null) {
            return ConfigurationUtil.getAuditHelper(servletContext);
        }

        return this.auditHelper;
    }
}