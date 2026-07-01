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
package org.picketlink.identity.federation.bindings.wildfly.elytron;

import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.ServletContext;
import org.picketlink.identity.federation.bindings.wildfly.sp.SPFormAuthenticationMechanism;

/**
 * Registry of {@link SPFormAuthenticationMechanism} instances keyed by deployment context path.
 */
public final class PicketLinkElytronSpMechanismRegistry {

    public static final String SERVLET_CONTEXT_ATTRIBUTE =
            "org.picketlink.identity.federation.bindings.wildfly.elytron.sp-mechanism";

    /** Deployment metadata consumed by {@link org.picketlink.identity.federation.bindings.wildfly.sp.PicketLinkSamlServletContextListener}. */
    public static final String LOGIN_PAGE_ATTRIBUTE =
            "org.picketlink.identity.federation.bindings.wildfly.elytron.login-page";

    /** Deployment metadata consumed by {@link org.picketlink.identity.federation.bindings.wildfly.sp.PicketLinkSamlServletContextListener}. */
    public static final String ERROR_PAGE_ATTRIBUTE =
            "org.picketlink.identity.federation.bindings.wildfly.elytron.error-page";

    /** Session attribute used by {@code SPFormAuthenticationMechanism} after SAML completion. */
    public static final String FORM_ACCOUNT_NOTE = "picketlink.form.account";

    private PicketLinkElytronSpMechanismRegistry() {
    }

    public static void register(ServletContext servletContext, SPFormAuthenticationMechanism mechanism) {
        if (servletContext == null || mechanism == null) {
            return;
        }
        servletContext.setAttribute(SERVLET_CONTEXT_ATTRIBUTE, mechanism);
    }

    public static Object lookupMechanism(ServletContext servletContext) {
        if (servletContext == null) {
            return null;
        }
        return servletContext.getAttribute(SERVLET_CONTEXT_ATTRIBUTE);
    }

    public static Object lookupMechanism(HttpServerExchange exchange) {
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext != null) {
            ServletContext servletContext = servletRequestContext.getCurrentServletContext();
            if (servletContext != null) {
                return servletContext.getAttribute(SERVLET_CONTEXT_ATTRIBUTE);
            }
        }
        return null;
    }

    /** @deprecated Use {@link #lookupMechanism(HttpServerExchange)} from deployment classloader via reflection. */
    @Deprecated
    public static SPFormAuthenticationMechanism lookup(HttpServerExchange exchange) {
        Object mechanism = lookupMechanism(exchange);
        return mechanism instanceof SPFormAuthenticationMechanism ? (SPFormAuthenticationMechanism) mechanism : null;
    }
}
