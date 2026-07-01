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
package org.picketlink.identity.federation.bindings.wildfly.auth;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkElytronIdentityCompletion;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlPrincipal;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlSession;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;

/**
 * Stores and restores Elytron {@code SecurityIdentity} instances in the HTTP session using the
 * same attachment key as {@code HttpAuthenticator}, so subsequent requests can re-establish the
 * Elytron thread-local identity via {@code restoreIdentity()}.
 */
public final class ElytronSessionIdentitySupport {

    /**
     * Session key used by Elytron {@code HttpAuthenticator} for {@code CachedIdentity}.
     */
    public static final String SESSION_KEY = PicketLinkElytronIdentityCompletion.CACHED_IDENTITY_SESSION_KEY;

    /** @deprecated Use {@link #SESSION_KEY}; kept for compatibility with earlier bridge builds. */
    @Deprecated
    public static final String LEGACY_SESSION_KEY = "org.picketlink.elytron.cached-identity";

    private ElytronSessionIdentitySupport() {
    }

    public static void store(
            HttpServerExchange exchange, SecurityContext securityContext, SecurityIdentity securityIdentity, String mechanism) {
        if (exchange == null || securityContext == null || securityIdentity == null) {
            return;
        }
        HttpScope sessionScope = resolveSessionScope(securityContext);
        if (sessionScope != null) {
            if (!sessionScope.exists()) {
                sessionScope.create();
            }
            sessionScope.setAttachment(SESSION_KEY, new CachedIdentity(mechanism, true, securityIdentity));
            return;
        }
        storeInHttpSession(exchange, securityIdentity, mechanism);
    }

    public static void storeFromAccount(
            HttpServerExchange exchange, SecurityContext securityContext, Account account, String mechanism) {
        if (account == null) {
            return;
        }
        try {
            Object securityIdentity = account.getClass().getMethod("getSecurityIdentity").invoke(account);
            if (securityIdentity instanceof SecurityIdentity) {
                store(exchange, securityContext, (SecurityIdentity) securityIdentity, mechanism);
                storePicketLinkSession(exchange, securityContext, account, mechanism);
            }
        } catch (Exception ignored) {
        }
    }

    public static boolean restore(HttpServerExchange exchange, SecurityContext securityContext, Account account) {
        if (!ElytronSecurityContextSupport.isElytronSecurityContext(securityContext)) {
            return false;
        }
        CachedIdentity cachedIdentity = readCachedIdentity(securityContext, exchange);
        if (cachedIdentity == null) {
            return false;
        }
        try {
            SecurityIdentity securityIdentity = cachedIdentity.getSecurityIdentity();
            if (securityIdentity == null) {
                return false;
            }
            String mechanism = cachedIdentity.getMechanismName();
            if (mechanism == null || mechanism.isBlank()) {
                mechanism = PicketLinkElytronIdentityCompletion.MECHANISM_NAME;
            }
            return ElytronSecurityContextSupport.completeAuthentication(securityContext, securityIdentity, mechanism);
        } catch (Exception ignored) {
            return false;
        }
    }

    public static void clear(HttpSession session) {
        if (session != null) {
            session.removeAttribute(SESSION_KEY);
            session.removeAttribute(LEGACY_SESSION_KEY);
        }
    }

    private static CachedIdentity readCachedIdentity(SecurityContext securityContext, HttpServerExchange exchange) {
        HttpScope sessionScope = resolveSessionScope(securityContext);
        if (sessionScope != null && sessionScope.exists()) {
            Object attachment = sessionScope.getAttachment(SESSION_KEY);
            if (attachment instanceof CachedIdentity) {
                return (CachedIdentity) attachment;
            }
            attachment = sessionScope.getAttachment(LEGACY_SESSION_KEY);
            if (attachment instanceof CachedIdentity) {
                return (CachedIdentity) attachment;
            }
        }
        HttpSession session = currentSession(exchange, false);
        if (session == null) {
            return null;
        }
        Object attribute = session.getAttribute(SESSION_KEY);
        if (attribute instanceof CachedIdentity) {
            return (CachedIdentity) attribute;
        }
        attribute = session.getAttribute(LEGACY_SESSION_KEY);
        return attribute instanceof CachedIdentity ? (CachedIdentity) attribute : null;
    }

    private static HttpScope resolveSessionScope(SecurityContext securityContext) {
        ElytronHttpExchange httpExchange = PicketLinkElytronIdentityCompletion.resolveHttpExchange(securityContext);
        if (httpExchange == null) {
            return null;
        }
        return httpExchange.getScope(Scope.SESSION);
    }

    private static void storeInHttpSession(HttpServerExchange exchange, SecurityIdentity securityIdentity, String mechanism) {
        HttpSession session = currentSession(exchange, true);
        if (session != null) {
            session.setAttribute(SESSION_KEY, new CachedIdentity(mechanism, true, securityIdentity));
            session.removeAttribute(LEGACY_SESSION_KEY);
        }
    }

    private static void storePicketLinkSession(
            HttpServerExchange exchange, SecurityContext securityContext, Account account, String mechanism) {
        HttpScope sessionScope = resolveSessionScope(securityContext);
        if (sessionScope == null || account == null) {
            return;
        }
        if (!sessionScope.exists()) {
            sessionScope.create();
        }
        PicketLinkSamlPrincipal principal;
        if (account.getPrincipal() instanceof PicketLinkSamlPrincipal) {
            principal = (PicketLinkSamlPrincipal) account.getPrincipal();
        } else {
            principal = new PicketLinkSamlPrincipal(account.getPrincipal().getName(), account.getRoles());
        }
        sessionScope.setAttachment(PicketLinkSamlSession.SESSION_KEY, new PicketLinkSamlSession(principal));
    }

    private static HttpSession currentSession(HttpServerExchange exchange, boolean create) {
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return null;
        }
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        return request.getSession(create);
    }
}
