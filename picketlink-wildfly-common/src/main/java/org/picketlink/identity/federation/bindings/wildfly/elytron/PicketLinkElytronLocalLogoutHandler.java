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

import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSessionIdentitySupport;
import org.picketlink.identity.federation.core.saml.workflow.ServiceProviderSAMLWorkflow;

/**
 * Handles SP logout requests before Elytron restores a cached identity, which would otherwise
 * skip {@link org.picketlink.identity.federation.bindings.wildfly.sp.SPFormAuthenticationMechanism}.
 * <ul>
 *   <li>{@code LLO=true} — local logout page and session invalidation</li>
 *   <li>{@code GLO=true} — clear Elytron cache only (SAML session attributes remain for LogoutRequest)</li>
 * </ul>
 */
public final class PicketLinkElytronLocalLogoutHandler implements HttpHandler {

    public static HandlerWrapper wrapper(SPType spType) {
        return next -> new PicketLinkElytronLocalLogoutHandler(spType, next);
    }

    private final SPType spType;
    private final HttpHandler next;

    private PicketLinkElytronLocalLogoutHandler(SPType spType, HttpHandler next) {
        this.spType = spType;
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            next.handleRequest(exchange);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();
        ServiceProviderSAMLWorkflow workflow = new ServiceProviderSAMLWorkflow();

        if (workflow.isGlobalLogout(request)) {
            clearElytronCachedIdentity(request.getSession(false));
            next.handleRequest(exchange);
            return;
        }

        if (!workflow.isLocalLogoutRequest(request)) {
            next.handleRequest(exchange);
            return;
        }

        String logoutPage = spType.getLogOutPage();
        if (logoutPage == null || logoutPage.isBlank()) {
            logoutPage = GeneralConstants.LOGOUT_PAGE_NAME;
        }
        if (!logoutPage.startsWith("/")) {
            logoutPage = "/" + logoutPage;
        }

        HttpSession session = request.getSession(false);
        workflow.sendToLogoutPage(request, response, session, request.getServletContext(), logoutPage);
    }

    private static void clearElytronCachedIdentity(HttpSession session) {
        ElytronSessionIdentitySupport.clear(session);
        if (session != null) {
            session.removeAttribute(PicketLinkSamlSession.SESSION_KEY);
        }
    }
}
