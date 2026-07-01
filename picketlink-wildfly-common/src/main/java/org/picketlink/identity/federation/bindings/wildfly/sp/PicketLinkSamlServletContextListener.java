/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026, Red Hat, Inc., and individual contributors
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

import io.undertow.server.handlers.form.FormParserFactory;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.http.HttpServletRequest;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkElytronSpMechanismRegistry;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.SAMLConfigurationProvider;

/**
 * Registers {@link SPFormAuthenticationMechanism} on the runtime {@link ServletContext} for Elytron
 * HTTP authentication (Keycloak {@code KeycloakConfigurationServletListener} pattern).
 */
public class PicketLinkSamlServletContextListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext servletContext = event.getServletContext();
        if (PicketLinkElytronSpMechanismRegistry.lookupMechanism(servletContext) != null) {
            return;
        }
        try {
            PicketLinkType configuration = ConfigurationUtil.getConfiguration(servletContext);
            if (configuration == null) {
                return;
            }
            ProviderType providerType = configuration.getIdpOrSP();
            if (!SPType.class.isInstance(providerType)) {
                return;
            }
            String loginPage = stringContextAttribute(servletContext, PicketLinkElytronSpMechanismRegistry.LOGIN_PAGE_ATTRIBUTE);
            String errorPage = stringContextAttribute(servletContext, PicketLinkElytronSpMechanismRegistry.ERROR_PAGE_ATTRIBUTE);
            SAMLConfigurationProvider configurationProvider = ConfigurationUtil.getConfigurationProvider(servletContext);
            PicketLinkAuditHelper auditHelper = configuration.isEnableAudit()
                    ? ConfigurationUtil.getAuditHelper(servletContext)
                    : null;
            FormParserFactory formParserFactory = FormParserFactory.builder().build();
            SPFormAuthenticationMechanism mechanism;
            if (configurationProvider != null) {
                mechanism = new SPFormAuthenticationMechanism(
                        formParserFactory, HttpServletRequest.FORM_AUTH, loginPage, errorPage,
                        servletContext, configurationProvider, auditHelper);
            } else {
                mechanism = new SPFormAuthenticationMechanism(
                        formParserFactory, HttpServletRequest.FORM_AUTH, loginPage, errorPage,
                        servletContext, configuration, auditHelper);
            }
            PicketLinkElytronSpMechanismRegistry.register(servletContext, mechanism);
        } catch (ProcessingException | ConfigurationException e) {
            throw new RuntimeException("Could not register PicketLink SAML SP mechanism.", e);
        }
    }

    private static String stringContextAttribute(ServletContext servletContext, String name) {
        Object value = servletContext.getAttribute(name);
        return value instanceof String ? (String) value : null;
    }
}
