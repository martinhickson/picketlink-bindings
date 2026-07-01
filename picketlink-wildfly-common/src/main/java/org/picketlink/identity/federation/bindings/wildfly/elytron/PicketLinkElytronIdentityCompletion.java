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

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import java.lang.reflect.Field;
import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.security.auth.callback.CallbackHandler;
import org.jboss.logging.Logger;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronIdentityEstablishmentResult;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSecurityContextSupport;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSessionIdentitySupport;
import org.picketlink.identity.federation.bindings.wildfly.auth.JaasElytronAuthenticationBridgeContext;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * Completes Elytron authentication using the Keycloak adapter callback + {@code HttpServerRequest} pattern.
 */
public final class PicketLinkElytronIdentityCompletion {

    public static final String MECHANISM_NAME = "PICKETLINK-SAML";

    /** Same key as {@code org.wildfly.security.http.HttpAuthenticator}. */
    public static final String CACHED_IDENTITY_SESSION_KEY =
            "org.wildfly.security.http.HttpAuthenticator.authenticated-identity";

    private static final Logger LOGGER = Logger.getLogger(PicketLinkElytronIdentityCompletion.class);

    private PicketLinkElytronIdentityCompletion() {
    }

    public static ElytronIdentityEstablishmentResult complete(JaasElytronAuthenticationBridgeContext context) {
        if (context == null || context.getSecurityContext() == null || context.getUsername() == null) {
            return ElytronIdentityEstablishmentResult.failure();
        }

        SecurityContext securityContext = context.getSecurityContext();
        ElytronHttpExchange httpExchange = resolveHttpExchange(securityContext);
        SecurityDomain securityDomain = resolveSecurityDomain(securityContext);
        if (httpExchange == null || securityDomain == null) {
            LOGGER.trace("Direct Elytron completion skipped; Elytron exchange or domain unavailable.");
            return ElytronIdentityEstablishmentResult.failure();
        }

        try {
            PicketLinkSamlPrincipal principal = createPrincipal(context);
            SecurityIdentity securityIdentity = authorize(securityDomain, principal);
            if (securityIdentity == null) {
                return fallbackAdHocCompletion(context);
            }

            storeSession(httpExchange, principal, securityIdentity);

            if (PicketLinkElytronUndertowBridgeContext.isDeferred()) {
                return ElytronIdentityEstablishmentResult.success(context.getUndertowAccount(), true);
            }

            httpExchange.authenticationComplete(securityIdentity, MECHANISM_NAME);
            ElytronSecurityContextSupport.completeAuthentication(securityContext, securityIdentity, MECHANISM_NAME);
            ElytronSessionIdentitySupport.storeFromAccount(
                    context.getHttpServerExchange(), securityContext, securityContext.getAuthenticatedAccount(), MECHANISM_NAME);

            Account account = securityContext.getAuthenticatedAccount();
            if (account == null || account.getRoles() == null || account.getRoles().isEmpty()) {
                return fallbackAdHocCompletion(context);
            }
            return ElytronIdentityEstablishmentResult.success(account, true);
        } catch (Exception e) {
            LOGGER.trace("Elytron identity completion failed.", e);
            return fallbackAdHocCompletion(context);
        }
    }

    private static ElytronIdentityEstablishmentResult fallbackAdHocCompletion(
            JaasElytronAuthenticationBridgeContext context) {
        SecurityContext securityContext = context.getSecurityContext();
        Account undertowAccount = context.getUndertowAccount();
        if (!ElytronSecurityContextSupport.isElytronSecurityContext(securityContext) || undertowAccount == null) {
            return ElytronIdentityEstablishmentResult.failure();
        }
        if (!ElytronSecurityContextSupport.completeAuthentication(securityContext, undertowAccount, MECHANISM_NAME)) {
            return ElytronIdentityEstablishmentResult.failure();
        }
        ElytronSessionIdentitySupport.storeFromAccount(
                context.getHttpServerExchange(), securityContext, securityContext.getAuthenticatedAccount(), MECHANISM_NAME);
        Account account = securityContext.getAuthenticatedAccount();
        if (account == null || account.getRoles() == null || account.getRoles().isEmpty()) {
            return ElytronIdentityEstablishmentResult.failure();
        }
        return ElytronIdentityEstablishmentResult.success(account, true);
    }

    public static SecurityIdentity authorizeFromSession(
            HttpServerRequest request, CallbackHandler callbackHandler, SecurityDomain securityDomain) {
        PicketLinkSamlSession session = readSession(request);
        if (session == null) {
            return null;
        }
        PicketLinkSamlPrincipal principal = session.getPrincipal();
        SecurityIdentity identity = PicketLinkSecurityIdentityUtil.authorize(callbackHandler, principal);
        if (identity != null) {
            identity = PicketLinkSecurityIdentityFactory.attachRoleMappers(identity, principal.getRoles());
        } else if (securityDomain != null) {
            identity = PicketLinkSecurityIdentityFactory.authorize(securityDomain, principal);
        }
        return identity;
    }

    public static PicketLinkSamlSession readSession(HttpServerRequest request) {
        HttpScope sessionScope = request.getScope(Scope.SESSION);
        if (sessionScope == null || !sessionScope.exists()) {
            return null;
        }
        Object attachment = sessionScope.getAttachment(PicketLinkSamlSession.SESSION_KEY);
        return attachment instanceof PicketLinkSamlSession ? (PicketLinkSamlSession) attachment : null;
    }

    public static void storeSession(HttpServerRequest request, PicketLinkSamlPrincipal principal, SecurityIdentity identity) {
        HttpScope sessionScope = request.getScope(Scope.SESSION);
        if (sessionScope != null) {
            if (!sessionScope.exists()) {
                sessionScope.create();
            }
            sessionScope.setAttachment(PicketLinkSamlSession.SESSION_KEY, new PicketLinkSamlSession(principal));
            sessionScope.setAttachment(
                    CACHED_IDENTITY_SESSION_KEY, new CachedIdentity(MECHANISM_NAME, true, identity));
        }
    }

    private static void storeSession(
            ElytronHttpExchange httpExchange, PicketLinkSamlPrincipal principal, SecurityIdentity identity) {
        HttpScope sessionScope = httpExchange.getScope(Scope.SESSION);
        if (sessionScope != null) {
            if (!sessionScope.exists()) {
                sessionScope.create();
            }
            sessionScope.setAttachment(PicketLinkSamlSession.SESSION_KEY, new PicketLinkSamlSession(principal));
            sessionScope.setAttachment(
                    CACHED_IDENTITY_SESSION_KEY, new CachedIdentity(MECHANISM_NAME, true, identity));
        }
    }

    private static SecurityIdentity authorize(SecurityDomain securityDomain, PicketLinkSamlPrincipal principal) {
        try {
            return PicketLinkSecurityIdentityFactory.authorize(securityDomain, principal);
        } catch (Exception e) {
            LOGGER.trace("Unable to authorize SAML principal via Elytron security domain.", e);
            return null;
        }
    }

    private static PicketLinkSamlPrincipal createPrincipal(JaasElytronAuthenticationBridgeContext context) {
        Set<String> roles = new LinkedHashSet<>();
        if (context.getRoles() != null) {
            roles.addAll(context.getRoles());
        }
        if (context.getUndertowAccount() != null && context.getUndertowAccount().getRoles() != null) {
            roles.addAll(context.getUndertowAccount().getRoles());
        }
        Principal samlPrincipal = context.getSamlPrincipal();
        String username = context.getUsername();
        if (samlPrincipal != null && samlPrincipal.getName() != null) {
            username = samlPrincipal.getName();
        }
        return new PicketLinkSamlPrincipal(username, roles);
    }

    public static ElytronHttpExchange resolveHttpExchange(SecurityContext securityContext) {
        try {
            Field httpExchangeField = findField(securityContext.getClass(), "httpExchange");
            if (httpExchangeField == null) {
                return null;
            }
            httpExchangeField.setAccessible(true);
            Object value = httpExchangeField.get(securityContext);
            return value instanceof ElytronHttpExchange ? (ElytronHttpExchange) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    static SecurityDomain resolveSecurityDomain(SecurityContext securityContext) {
        try {
            Field securityDomainField = findField(securityContext.getClass(), "securityDomain");
            if (securityDomainField == null) {
                return null;
            }
            securityDomainField.setAccessible(true);
            Object value = securityDomainField.get(securityContext);
            return value instanceof SecurityDomain ? (SecurityDomain) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}
