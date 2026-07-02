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

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;
import javax.security.auth.callback.CallbackHandler;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSecurityContextSupport;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpServerRequest;

/**
 * Bridges Elytron {@link HttpServerRequest} evaluation to the Undertow {@link SPFormAuthenticationMechanism},
 * which Elytron {@code SecurityContextImpl} does not invoke directly.
 */
public final class PicketLinkElytronUndertowBridge {

    private static final String SAML_RESPONSE_PARAMETER = "SAMLResponse";
    private static final String SAML_REQUEST_PARAMETER = "SAMLRequest";

    private PicketLinkElytronUndertowBridge() {
    }

    public static boolean shouldDelegate(HttpServerRequest request) {
        if (request == null) {
            return false;
        }
        HttpServerExchange exchange = resolveExchange(request);
        if (exchange == null) {
            return false;
        }
        if (PicketLinkElytronSpMechanismRegistry.lookupMechanism(exchange) != null) {
            return true;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext != null) {
            HttpServletRequest servletRequest = (HttpServletRequest) servletRequestContext.getServletRequest();
            if (hasParameter(servletRequest, SAML_RESPONSE_PARAMETER)
                    || hasParameter(servletRequest, SAML_REQUEST_PARAMETER)) {
                return true;
            }
            HttpSession session = servletRequest.getSession(false);
            if (session != null && session.getAttribute(PicketLinkElytronSpMechanismRegistry.FORM_ACCOUNT_NOTE) != null) {
                return true;
            }
        }
        return hasSamlParameter(request, SAML_RESPONSE_PARAMETER)
                || hasSamlParameter(request, SAML_REQUEST_PARAMETER);
    }

    public static boolean delegateAuthenticate(HttpServerRequest request) {
        return delegateAuthenticate(request, null);
    }

    public static boolean delegateAuthenticate(HttpServerRequest request, CallbackHandler callbackHandler) {
        HttpServerExchange exchange = resolveExchange(request);
        if (exchange == null) {
            return false;
        }
        SecurityContext securityContext = exchange.getSecurityContext();
        if (securityContext == null) {
            return false;
        }
        Object mechanism = PicketLinkElytronSpMechanismRegistry.lookupMechanism(exchange);
        if (mechanism == null) {
            return false;
        }

        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        ClassLoader mechanismLoader = mechanism.getClass().getClassLoader();
        try {
            PicketLinkElytronUndertowBridgeContext.setDeferred(true);
            Thread.currentThread().setContextClassLoader(mechanismLoader != null ? mechanismLoader : previous);
            if (!hasSamlTraffic(exchange, request) && securityContext.isAuthenticationRequired()) {
                if (invokeSendChallenge(mechanism, exchange, securityContext, request)) {
                    return true;
                }
            }
            Method authenticate = mechanism.getClass().getMethod(
                    "authenticate", HttpServerExchange.class, SecurityContext.class);
            Object outcome = authenticate.invoke(mechanism, exchange, securityContext);
            if (AuthenticationMechanism.AuthenticationMechanismOutcome.AUTHENTICATED.equals(outcome)) {
                return completeDelegatedAuthentication(request, securityContext, callbackHandler);
            }
            if (AuthenticationMechanism.AuthenticationMechanismOutcome.NOT_AUTHENTICATED.equals(outcome)) {
                if (!isResponseCommitted(exchange)
                        && securityContext.isAuthenticationRequired()
                        && invokeSendChallenge(mechanism, exchange, securityContext, request)) {
                    return true;
                }
                request.authenticationInProgress(response -> {});
                return true;
            }
            return false;
        } catch (ReflectiveOperationException e) {
            return false;
        } finally {
            PicketLinkElytronUndertowBridgeContext.clear();
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private static boolean invokeSendChallenge(
            Object mechanism, HttpServerExchange exchange, SecurityContext securityContext, HttpServerRequest request)
            throws ReflectiveOperationException {
        Method sendChallenge = mechanism.getClass().getMethod(
                "sendChallenge", HttpServerExchange.class, SecurityContext.class);
        Object challengeResult = sendChallenge.invoke(mechanism, exchange, securityContext);
        if (isChallengeSent(challengeResult) || isResponseCommitted(exchange)) {
            request.authenticationInProgress(response -> {});
            return true;
        }
        return false;
    }

    private static boolean hasSamlTraffic(HttpServerExchange exchange, HttpServerRequest request) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext != null) {
            HttpServletRequest servletRequest = (HttpServletRequest) servletRequestContext.getServletRequest();
            if (hasParameter(servletRequest, SAML_RESPONSE_PARAMETER)
                    || hasParameter(servletRequest, SAML_REQUEST_PARAMETER)) {
                return true;
            }
            HttpSession session = servletRequest.getSession(false);
            if (session != null && session.getAttribute(PicketLinkElytronSpMechanismRegistry.FORM_ACCOUNT_NOTE) != null) {
                return true;
            }
        }
        return hasSamlParameter(request, SAML_RESPONSE_PARAMETER)
                || hasSamlParameter(request, SAML_REQUEST_PARAMETER);
    }

    private static boolean completeDelegatedAuthentication(
            HttpServerRequest request, SecurityContext securityContext, CallbackHandler callbackHandler) {
        Account savedAccount = readSavedAccount(securityContext);
        if (savedAccount != null && callbackHandler != null) {
            Set<String> roles = savedAccount.getRoles();
            if (roles != null && !roles.isEmpty()) {
                PicketLinkSamlPrincipal principal = toSamlPrincipal(savedAccount, roles);
                org.wildfly.security.auth.server.SecurityIdentity identity =
                        PicketLinkSecurityIdentityUtil.authorize(callbackHandler, principal);
                if (identity != null) {
                    identity = PicketLinkSecurityIdentityFactory.attachRoleMappers(identity, roles);
                    PicketLinkElytronIdentityCompletion.storeSession(request, principal, identity);
                    request.authenticationComplete();
                    return true;
                }
            }
        }

        PicketLinkSamlSession samlSession = PicketLinkElytronIdentityCompletion.readSession(request);
        if (samlSession != null && callbackHandler != null) {
            org.wildfly.security.auth.server.SecurityIdentity identity =
                    PicketLinkElytronIdentityCompletion.authorizeFromSession(request, callbackHandler, null);
            if (identity != null) {
                PicketLinkElytronIdentityCompletion.storeSession(request, samlSession.getPrincipal(), identity);
                request.authenticationComplete();
                return true;
            }
        }

        Account account = securityContext.getAuthenticatedAccount();
        if (account == null) {
            account = readSavedAccount(securityContext);
        }

        Set<String> roles = account != null ? account.getRoles() : null;
        if ((roles == null || roles.isEmpty()) && account == null) {
            account = readSavedAccount(securityContext);
            roles = account != null ? account.getRoles() : null;
        }
        if (roles == null || roles.isEmpty()) {
            roles = readSavedAccountRoles(securityContext);
        }

        if (callbackHandler != null && account != null && roles != null && !roles.isEmpty()) {
            PicketLinkSamlPrincipal principal = toSamlPrincipal(account, roles);
            org.wildfly.security.auth.server.SecurityIdentity identity =
                    PicketLinkSecurityIdentityUtil.authorize(callbackHandler, principal);
            if (identity != null) {
                identity = PicketLinkSecurityIdentityFactory.attachRoleMappers(identity, roles);
                PicketLinkElytronIdentityCompletion.storeSession(request, principal, identity);
                request.authenticationComplete();
                return true;
            }
        }

        if (account == null) {
            return false;
        }

        if (roles == null || roles.isEmpty()) {
            roles = readSavedAccountRoles(securityContext);
        }

        org.wildfly.security.auth.server.SecurityIdentity securityIdentity = extractSecurityIdentity(account);
        if (securityIdentity == null && ElytronSecurityContextSupport.isElytronSecurityContext(securityContext)) {
            securityIdentity = ElytronSecurityContextSupport.createSecurityIdentity(
                    securityContext, toSamlPrincipal(account, roles), roles);
        }
        if (securityIdentity == null || roles == null || roles.isEmpty()) {
            return false;
        }

        if (account.getRoles() == null || account.getRoles().isEmpty()) {
            securityIdentity = PicketLinkSecurityIdentityFactory.attachRoleMappers(securityIdentity, roles);
        }

        PicketLinkElytronIdentityCompletion.storeSession(request, toSamlPrincipal(account, roles), securityIdentity);
        request.authenticationComplete();
        return true;
    }

    private static Account readSavedAccount(SecurityContext securityContext) {
        HttpServerExchange exchange = resolveExchangeFromContext(securityContext);
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return null;
        }
        HttpSession session = ((HttpServletRequest) servletRequestContext.getServletRequest()).getSession(false);
        if (session == null) {
            return null;
        }
        Object saved = session.getAttribute(PicketLinkElytronSpMechanismRegistry.FORM_ACCOUNT_NOTE);
        return saved instanceof Account ? (Account) saved : null;
    }

    private static Set<String> readSavedAccountRoles(SecurityContext securityContext) {
        HttpServerExchange exchange = resolveExchangeFromContext(securityContext);
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return null;
        }
        HttpSession session = ((HttpServletRequest) servletRequestContext.getServletRequest()).getSession(false);
        if (session == null) {
            return null;
        }
        Object saved = session.getAttribute(PicketLinkElytronSpMechanismRegistry.FORM_ACCOUNT_NOTE);
        if (saved instanceof Account) {
            return ((Account) saved).getRoles();
        }
        return null;
    }

    private static HttpServerExchange resolveExchangeFromContext(SecurityContext securityContext) {
        ElytronHttpExchange httpExchange = PicketLinkElytronIdentityCompletion.resolveHttpExchange(securityContext);
        if (httpExchange == null) {
            return null;
        }
        try {
            Field exchangeField = ElytronHttpExchange.class.getDeclaredField("httpServerExchange");
            exchangeField.setAccessible(true);
            Object value = exchangeField.get(httpExchange);
            return value instanceof HttpServerExchange ? (HttpServerExchange) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    public static HttpServerExchange resolveExchange(HttpServerRequest request) {
        return PicketLinkElytronHttpFacade.resolveExchange(request);
    }

    private static SecurityIdentity extractSecurityIdentity(Account account) {
        try {
            Object value = account.getClass().getMethod("getSecurityIdentity").invoke(account);
            return value instanceof SecurityIdentity ? (SecurityIdentity) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static PicketLinkSamlPrincipal toSamlPrincipal(Account account, Set<String> roles) {
        if (account.getPrincipal() instanceof PicketLinkSamlPrincipal) {
            return (PicketLinkSamlPrincipal) account.getPrincipal();
        }
        return new PicketLinkSamlPrincipal(account.getPrincipal().getName(), roles);
    }

    private static boolean hasSamlParameter(HttpServerRequest request, String name) {
        String value = request.getFirstParameterValue(name);
        return value != null && !value.isBlank();
    }

    private static boolean hasParameter(HttpServletRequest request, String name) {
        if (request == null) {
            return false;
        }
        String value = request.getParameter(name);
        return value != null && !value.isBlank();
    }

    private static boolean isResponseCommitted(HttpServerExchange exchange) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return false;
        }
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();
        return response != null && response.isCommitted();
    }

    private static boolean isChallengeSent(Object challengeResult) {
        if (challengeResult == null) {
            return false;
        }
        try {
            Method method = challengeResult.getClass().getMethod("isChallengeSent");
            return Boolean.TRUE.equals(method.invoke(challengeResult));
        } catch (ReflectiveOperationException e) {
            return false;
        }
    }
}
