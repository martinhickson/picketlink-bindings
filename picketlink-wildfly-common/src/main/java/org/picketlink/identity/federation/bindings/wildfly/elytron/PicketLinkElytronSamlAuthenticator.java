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
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.lang.reflect.Method;
import java.util.ArrayList;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronIdentityEstablishmentResult;
import org.picketlink.identity.federation.bindings.wildfly.auth.JaasBridgeElytronIdentityEstablishment;
import org.picketlink.identity.federation.bindings.wildfly.auth.JaasElytronAuthenticationBridgeContext;
import org.jboss.logging.Logger;
import org.picketlink.common.constants.GeneralConstants;

/**
 * Runs SAML SP authentication inside the Elytron HTTP mechanism (Keycloak {@code ElytronSamlAuthenticator} pattern).
 */
public final class PicketLinkElytronSamlAuthenticator {

    private static final Logger LOGGER = Logger.getLogger(PicketLinkElytronSamlAuthenticator.class);

    private PicketLinkElytronSamlAuthenticator() {
    }

    public static PicketLinkElytronAuthOutcome authenticate(PicketLinkElytronHttpFacade facade) {
        HttpServletRequest request = facade.getServletRequest();
        if (request != null && isGlobalLogout(request)) {
            facade.getSessionStore().logoutAccount();
        } else if (facade.getSessionStore().isLoggedIn()) {
            return PicketLinkElytronAuthOutcome.AUTHENTICATED;
        }

        Object spMechanism = facade.lookupSpMechanismObject();
        HttpServerExchange exchange = facade.getExchange();
        SecurityContext securityContext = facade.getSecurityContext();
        if (spMechanism == null || exchange == null) {
            LOGGER.debug("No SP deployment context for Elytron SAML evaluation.");
            return PicketLinkElytronAuthOutcome.NOT_AUTHENTICATED;
        }

        try {
            PicketLinkElytronCompletionContext.set(facade);
            return evaluate(facade, spMechanism, exchange, securityContext, request);
        } catch (Exception e) {
            LOGGER.debug("Elytron SAML evaluation failed.", e);
            return PicketLinkElytronAuthOutcome.NOT_AUTHENTICATED;
        } finally {
            PicketLinkElytronCompletionContext.clear();
        }
    }

    private static PicketLinkElytronAuthOutcome evaluate(
            PicketLinkElytronHttpFacade facade,
            Object spMechanism,
            HttpServerExchange exchange,
            SecurityContext securityContext,
            HttpServletRequest request) throws ReflectiveOperationException {
        String samlResponse = resolveSamlParameter(facade, request, GeneralConstants.SAML_RESPONSE_KEY);
        String samlRequest = resolveSamlParameter(facade, request, GeneralConstants.SAML_REQUEST_KEY);

        if (isNotNull(samlResponse) || isNotNull(samlRequest)) {
            Object outcome = invokeAuthenticate(spMechanism, exchange, securityContext);
            return mapMechanismOutcome(facade, outcome);
        }

        if (request != null && isGlobalLogout(request)) {
            if (isAuthenticationRequired(securityContext)) {
                Object challengeResult = invokeSendChallenge(spMechanism, exchange, securityContext);
                if (isChallengeSent(challengeResult) || facade.isResponseCommitted()) {
                    facade.getSessionStore().saveRequest();
                    return PicketLinkElytronAuthOutcome.AUTHENTICATION_IN_PROGRESS;
                }
            }
            Object outcome = invokeAuthenticate(spMechanism, exchange, securityContext);
            return mapMechanismOutcome(facade, outcome);
        }

        if (request != null && isLocalLogout(request)) {
            Object outcome = invokeAuthenticate(spMechanism, exchange, securityContext);
            return mapMechanismOutcome(facade, outcome);
        }

        if (request != null && request.getUserPrincipal() != null) {
            Object outcome = invokeAuthenticate(spMechanism, exchange, securityContext);
            return mapMechanismOutcome(facade, outcome);
        }

        if (!isAuthenticationRequired(securityContext)) {
            return PicketLinkElytronAuthOutcome.NOT_AUTHENTICATED;
        }

        Object challengeResult = invokeSendChallenge(spMechanism, exchange, securityContext);
        if (isChallengeSent(challengeResult)) {
            facade.getSessionStore().saveRequest();
            return PicketLinkElytronAuthOutcome.AUTHENTICATION_IN_PROGRESS;
        }
        if (facade.isResponseCommitted()) {
            facade.getSessionStore().saveRequest();
            return PicketLinkElytronAuthOutcome.AUTHENTICATION_IN_PROGRESS;
        }

        Object outcome = invokeAuthenticate(spMechanism, exchange, securityContext);
        return mapMechanismOutcome(facade, outcome);
    }

    private static Object invokeSendChallenge(
            Object spMechanism, HttpServerExchange exchange, SecurityContext securityContext)
            throws ReflectiveOperationException {
        Method sendChallenge = findMethod(
                spMechanism.getClass(), "sendChallenge", HttpServerExchange.class, SecurityContext.class);
        if (sendChallenge == null) {
            return null;
        }
        return sendChallenge.invoke(spMechanism, exchange, securityContext);
    }

    private static Object invokeAuthenticate(
            Object spMechanism, HttpServerExchange exchange, SecurityContext securityContext)
            throws ReflectiveOperationException {
        Method authenticate = findMethod(
                spMechanism.getClass(), "authenticate", HttpServerExchange.class, SecurityContext.class);
        if (authenticate == null) {
            return null;
        }
        return authenticate.invoke(spMechanism, exchange, securityContext);
    }

    private static PicketLinkElytronAuthOutcome mapMechanismOutcome(
            PicketLinkElytronHttpFacade facade, Object outcome) {
        if (outcome instanceof Enum && "AUTHENTICATED".equals(((Enum<?>) outcome).name())) {
            return PicketLinkElytronAuthOutcome.AUTHENTICATED;
        }
        if (facade.isResponseCommitted()) {
            return PicketLinkElytronAuthOutcome.AUTHENTICATION_IN_PROGRESS;
        }
        return PicketLinkElytronAuthOutcome.NOT_AUTHENTICATED;
    }

    /**
     * Completes Elytron authentication after {@code SPFormAuthenticationMechanism} has processed SAML.
     * Must run from {@link PicketLinkSamlHttpServerAuthenticationMechanism}, not nested inside Undertow authenticate.
     */
    public static void completeDeferredAuthentication(PicketLinkElytronHttpFacade facade) {
        if (facade.getSessionStore().isLoggedIn()) {
            return;
        }
        HttpServerExchange exchange = facade.getExchange();
        if (exchange == null) {
            return;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        if (servletRequestContext == null) {
            return;
        }
        HttpSession session = ((HttpServletRequest) servletRequestContext.getServletRequest()).getSession(false);
        if (session == null) {
            return;
        }
        Object savedAccount = session.getAttribute(PicketLinkElytronSpMechanismRegistry.FORM_ACCOUNT_NOTE);
        if (!(savedAccount instanceof Account)) {
            return;
        }
        Account account = (Account) savedAccount;
        if (facade.isJaasBridgePath()) {
            completeJaasDeferredAuthentication(facade, exchange, account);
            return;
        }
        PicketLinkSamlPrincipal principal = new PicketLinkSamlPrincipal(
                account.getPrincipal().getName(), account.getRoles());
        facade.getSessionStore().restoreRequest();
        facade.completeAuthentication(principal);
    }

    private static void completeJaasDeferredAuthentication(
            PicketLinkElytronHttpFacade facade, HttpServerExchange exchange, Account account) {
        ServletContext servletContext = facade.getServletContext();
        JaasBridgeElytronIdentityEstablishment establishment =
                JaasBridgeElytronIdentityEstablishment.resolve(servletContext, null);
        if (establishment == null) {
            return;
        }
        JaasElytronAuthenticationBridgeContext bridgeContext = JaasElytronAuthenticationBridgeContext.builder()
                .httpServerExchange(exchange)
                .securityContext(facade.getSecurityContext())
                .servletContext(servletContext)
                .username(account.getPrincipal().getName())
                .roles(account.getRoles() != null ? new ArrayList<>(account.getRoles()) : null)
                .samlPrincipal(account.getPrincipal())
                .undertowAccount(account)
                .build();
        ElytronIdentityEstablishmentResult result = establishment.establish(bridgeContext);
        if (!result.isSuccess()) {
            PicketLinkSamlPrincipal principal = new PicketLinkSamlPrincipal(
                    account.getPrincipal().getName(), account.getRoles());
            facade.getSessionStore().restoreRequest();
            facade.completeAuthentication(principal);
        }
    }

    private static boolean isChallengeSent(Object challengeResult) {
        if (challengeResult == null) {
            return false;
        }
        try {
            Method method = challengeResult.getClass().getMethod("isChallengeSent");
            Object value = method.invoke(challengeResult);
            return Boolean.TRUE.equals(value);
        } catch (ReflectiveOperationException e) {
            return false;
        }
    }

    private static Method findMethod(Class<?> type, String name, Class<?>... parameterTypes) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getMethod(name, parameterTypes);
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }

    private static boolean isGlobalLogout(HttpServletRequest request) {
        String gloStr = request.getParameter(GeneralConstants.GLOBAL_LOGOUT);
        return gloStr != null && "true".equalsIgnoreCase(gloStr);
    }

    private static boolean isLocalLogout(HttpServletRequest request) {
        String lloStr = request.getParameter(GeneralConstants.LOCAL_LOGOUT);
        return lloStr != null && "true".equalsIgnoreCase(lloStr);
    }

    private static boolean isNotNull(String value) {
        return value != null && !value.isBlank();
    }

    private static boolean isAuthenticationRequired(SecurityContext securityContext) {
        return securityContext != null && securityContext.isAuthenticationRequired();
    }

    private static String resolveSamlParameter(
            PicketLinkElytronHttpFacade facade, HttpServletRequest request, String name) {
        if (request != null) {
            String value = request.getParameter(name);
            if (isNotNull(value)) {
                return value;
            }
        }
        String elytronValue = facade.getRequest().getFirstParameterValue(name);
        return isNotNull(elytronValue) ? elytronValue : null;
    }
}
