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
package org.picketlink.identity.federation.bindings.wildfly.metadata;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.FilterInfo;
import io.undertow.servlet.api.ServletInfo;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletContext;
import org.jboss.logging.Logger;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.identity.federation.web.metadata.AdminJsonMetadataPublishingFilter;
import org.picketlink.identity.federation.web.metadata.AdminMetadataJsonServlet;
import org.picketlink.identity.federation.web.metadata.MetadataPublishingConstants;
import org.picketlink.identity.federation.web.metadata.MetadataPublishingLoader;
import org.picketlink.identity.federation.web.metadata.MetadataPublishingSettings;
import org.picketlink.identity.federation.web.metadata.MetadataPublishingStartupLog;
import org.picketlink.identity.federation.web.metadata.XmlMetadataPublishingFilter;
import org.picketlink.identity.federation.web.servlets.saml.MetadataServlet;
import org.picketlink.identity.federation.web.servlets.saml.MetadataServletSP;

import java.util.Map;

/**
 * Eagerly installs metadata publishing gate filters and admin JSON servlet for deployments with a
 * {@code MetaDataProvider} configured.
 */
public class MetadataPublishingServletExtension implements ServletExtension {

    private static final Logger LOG = Logger.getLogger(MetadataPublishingServletExtension.class);

    @Override
    public void handleDeployment(final DeploymentInfo deploymentInfo, final ServletContext servletContext) {
        try {
            String configFile = resolveConfigFile(deploymentInfo);
            ProviderType providerType = resolveProviderType(deploymentInfo, servletContext, configFile);
            if (providerType == null || providerType.getMetaDataProvider() == null) {
                LOG.debug("Skipping metadata publishing extension for deployment ["
                        + deploymentInfo.getDeploymentName() + "] — no MetaDataProvider configured");
                return;
            }

            MetadataPublishingSettings settings = MetadataPublishingSettings.fromProvider(providerType);

            servletContext.setAttribute(MetadataPublishingConstants.SETTINGS_CONTEXT_ATTRIBUTE, settings);
            servletContext.setAttribute(MetadataPublishingConstants.CONFIG_FILE_CONTEXT_ATTRIBUTE, configFile);

            installXmlMetadataGate(deploymentInfo);
            installAdminJsonMetadataGate(deploymentInfo);
            installAdminJsonMetadataServlet(deploymentInfo, configFile);

            verifyInstallation(deploymentInfo);

            String contextPath = deploymentInfo.getContextPath();
            MetadataPublishingStartupLog.logDeploymentSummary(deploymentInfo.getDeploymentName(), contextPath, settings);

        } catch (RuntimeException e) {
            LOG.error("FATAL: PicketLink metadata publishing extension failed for deployment ["
                    + deploymentInfo.getDeploymentName() + "] — deployment aborted", e);
            throw e;
        } catch (Exception e) {
            LOG.error("FATAL: PicketLink metadata publishing extension failed for deployment ["
                    + deploymentInfo.getDeploymentName() + "] — deployment aborted", e);
            throw new RuntimeException("Failed to install PicketLink metadata publishing filters for deployment ["
                    + deploymentInfo.getDeploymentName() + "]", e);
        }
    }

    private void installXmlMetadataGate(DeploymentInfo deploymentInfo) {
        if (hasFilter(deploymentInfo, XmlMetadataPublishingFilter.class)) {
            return;
        }
        try {
            deploymentInfo.addFilter(new FilterInfo(
                    MetadataPublishingConstants.XML_GATE_FILTER_NAME,
                    XmlMetadataPublishingFilter.class));
            deploymentInfo.addFilterUrlMapping(
                    MetadataPublishingConstants.XML_GATE_FILTER_NAME,
                    MetadataPublishingConstants.XML_METADATA_PATH,
                    DispatcherType.REQUEST);
        } catch (Exception e) {
            throw new RuntimeException("Failed to register PicketLink XML metadata gate filter", e);
        }
    }

    private void installAdminJsonMetadataGate(DeploymentInfo deploymentInfo) {
        if (hasFilter(deploymentInfo, AdminJsonMetadataPublishingFilter.class)) {
            return;
        }
        try {
            deploymentInfo.addFilter(new FilterInfo(
                    MetadataPublishingConstants.ADMIN_JSON_GATE_FILTER_NAME,
                    AdminJsonMetadataPublishingFilter.class));
            deploymentInfo.addFilterUrlMapping(
                    MetadataPublishingConstants.ADMIN_JSON_GATE_FILTER_NAME,
                    MetadataPublishingConstants.ADMIN_JSON_METADATA_PATH,
                    DispatcherType.REQUEST);
        } catch (Exception e) {
            throw new RuntimeException("Failed to register PicketLink admin JSON metadata gate filter", e);
        }
    }

    private void installAdminJsonMetadataServlet(DeploymentInfo deploymentInfo, String configFile) {
        if (deploymentInfo.getServlets().containsKey(MetadataPublishingConstants.ADMIN_JSON_SERVLET_NAME)) {
            return;
        }
        try {
            ServletInfo servletInfo = new ServletInfo(
                    MetadataPublishingConstants.ADMIN_JSON_SERVLET_NAME,
                    AdminMetadataJsonServlet.class)
                    .addInitParam("configFile", configFile)
                    .setLoadOnStartup(1)
                    .addMapping(MetadataPublishingConstants.ADMIN_JSON_METADATA_PATH);
            deploymentInfo.addServlet(servletInfo);
        } catch (Exception e) {
            throw new RuntimeException("Failed to register PicketLink admin JSON metadata servlet", e);
        }
    }

    private void verifyInstallation(DeploymentInfo deploymentInfo) {
        if (!hasFilter(deploymentInfo, XmlMetadataPublishingFilter.class)) {
            throw new RuntimeException("PicketLink XML metadata gate filter is missing after installation");
        }
        if (!hasFilter(deploymentInfo, AdminJsonMetadataPublishingFilter.class)) {
            throw new RuntimeException("PicketLink admin JSON metadata gate filter is missing after installation");
        }
        if (!deploymentInfo.getServlets().containsKey(MetadataPublishingConstants.ADMIN_JSON_SERVLET_NAME)) {
            throw new RuntimeException("PicketLink admin JSON metadata servlet is missing after installation");
        }
    }

    private static boolean hasFilter(DeploymentInfo deploymentInfo, Class<?> filterClass) {
        for (FilterInfo filterInfo : deploymentInfo.getFilters().values()) {
            if (filterClass.isAssignableFrom(filterInfo.getFilterClass())) {
                return true;
            }
        }
        return false;
    }

    private static String resolveConfigFile(DeploymentInfo deploymentInfo) {
        for (ServletInfo servletInfo : deploymentInfo.getServlets().values()) {
            Class<?> servletClass = servletInfo.getServletClass();
            if (MetadataServlet.class.isAssignableFrom(servletClass)
                    || MetadataServletSP.class.isAssignableFrom(servletClass)) {
                Map<String, String> initParams = servletInfo.getInitParams();
                String configFile = initParams.get("configFile");
                if (configFile != null && !configFile.isEmpty()) {
                    return configFile;
                }
            }
        }
        return GeneralConstants.CONFIG_FILE_LOCATION;
    }

    private static ProviderType resolveProviderType(DeploymentInfo deploymentInfo, ServletContext servletContext,
            String configFile) throws ParsingException {
        ProviderType providerType = MetadataPublishingLoader.resolveProviderType(servletContext, configFile);
        if (providerType != null) {
            return providerType;
        }
        if (!GeneralConstants.CONFIG_FILE_LOCATION.equals(configFile)) {
            return MetadataPublishingLoader.resolveProviderType(servletContext, GeneralConstants.CONFIG_FILE_LOCATION);
        }
        return null;
    }
}
