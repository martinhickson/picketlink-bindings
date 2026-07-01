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
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.function.Consumer;
import javax.security.auth.callback.CallbackHandler;
import org.jboss.logging.Logger;
import org.picketlink.identity.federation.bindings.wildfly.auth.ElytronIdentityEstablishmentProvider;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;

/**
 * Elytron {@link HttpServerRequest} facade for SAML SP authentication (Keycloak {@code ElytronHttpFacade} pattern).
 */
public final class PicketLinkElytronHttpFacade {

    private static final Logger LOGGER = Logger.getLogger(PicketLinkElytronHttpFacade.class);

    private final HttpServerRequest request;
    private final CallbackHandler callbackHandler;
    private final PicketLinkElytronSessionStore sessionStore;
    private final HttpServerExchange exchange;
    private final ServletContext servletContext;

    private Consumer<HttpServerResponse> responseConsumer = response -> {};
    private Consumer<HttpServerResponse> afterAuthenticationComplete = response -> {};
    private boolean restored;

    public PicketLinkElytronHttpFacade(HttpServerRequest request, CallbackHandler callbackHandler) {
        this.request = request;
        this.callbackHandler = callbackHandler;
        this.exchange = resolveExchange(request);
        this.servletContext = resolveServletContext();
        this.sessionStore = new PicketLinkElytronSessionStore(this);
    }

    public HttpServerRequest getRequest() {
        return request;
    }

    public HttpServerExchange getExchange() {
        return exchange;
    }

    public SecurityContext getSecurityContext() {
        return exchange != null ? exchange.getSecurityContext() : null;
    }

    public ServletContext getServletContext() {
        return servletContext;
    }

    public PicketLinkElytronSessionStore getSessionStore() {
        return sessionStore;
    }

    public String getRequestUri() {
        URI uri = request.getRequestURI();
        return uri != null ? uri.toString() : null;
    }

    public boolean hasDeploymentContext() {
        return exchange != null && servletContext != null && lookupSpMechanismObject() != null;
    }

    public boolean isDirectPath() {
        if (servletContext == null) {
            return true;
        }
        String strategy = servletContext.getInitParameter(ElytronIdentityEstablishmentProvider.INIT_PARAM_STRATEGY);
        if (strategy == null || strategy.isBlank()) {
            strategy = System.getProperty(ElytronIdentityEstablishmentProvider.SYSTEM_PROPERTY_STRATEGY);
        }
        return strategy == null
                || strategy.isBlank()
                || ElytronIdentityEstablishmentProvider.STRATEGY_DIRECT.equalsIgnoreCase(strategy.trim());
    }

    public boolean isJaasBridgePath() {
        return !isDirectPath();
    }

    public Object lookupSpMechanismObject() {
        if (servletContext != null) {
            return PicketLinkElytronSpMechanismRegistry.lookupMechanism(servletContext);
        }
        return null;
    }

    public HttpServletRequest getServletRequest() {
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        return servletRequestContext != null
                ? (HttpServletRequest) servletRequestContext.getServletRequest()
                : null;
    }

    public HttpServletResponse getServletResponse() {
        if (exchange == null) {
            return null;
        }
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        return servletRequestContext != null
                ? (HttpServletResponse) servletRequestContext.getServletResponse()
                : null;
    }

    public boolean isResponseCommitted() {
        HttpServletResponse response = getServletResponse();
        return response != null && response.isCommitted();
    }

    void markRestored() {
        this.restored = true;
    }

    /**
     * Defers {@link HttpServerRequest#suspendRequest()} until the in-progress response is built (Keycloak pattern).
     */
    public void suspendRequest() {
        responseConsumer = responseConsumer.andThen(response -> request.suspendRequest());
    }

    /**
     * Resumes the original request saved by {@link #suspendRequest()}.
     */
    public boolean resumeRequest() {
        restored = request.resumeRequest();
        return restored;
    }

    void runAfterAuthenticationComplete(Consumer<HttpServerResponse> consumer) {
        this.afterAuthenticationComplete = consumer;
    }

    /**
     * Completes Elytron authentication via callback pipeline and caches identity in session scope.
     */
    public boolean completeAuthentication(PicketLinkSamlPrincipal principal) {
        SecurityIdentity securityIdentity = PicketLinkSecurityIdentityUtil.authorize(callbackHandler, principal);
        if (securityIdentity == null) {
            LOGGER.debugf("Callback authorization failed for principal [%s]", principal.getName());
            return false;
        }
        securityIdentity = PicketLinkSecurityIdentityFactory.attachRoleMappers(securityIdentity, principal.getRoles());
        sessionStore.saveAccount(principal);
        PicketLinkElytronIdentityCompletion.storeSession(request, principal, securityIdentity);
        request.authenticationComplete(response -> {
            if (!restored) {
                responseConsumer.accept(response);
            }
            afterAuthenticationComplete.accept(response);
        }, () -> sessionStore.logoutAccount());
        return true;
    }

    public void authenticationInProgress() {
        request.authenticationInProgress(response -> responseConsumer.accept(response));
    }

    public void noAuthenticationInProgress() {
        request.noAuthenticationInProgress(response -> responseConsumer.accept(response));
    }

    public void authenticationFailed() {
        request.authenticationFailed("Authentication Failed", response -> responseConsumer.accept(response));
    }

    private ServletContext resolveServletContext() {
        if (exchange != null) {
            ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
            if (servletRequestContext != null) {
                return servletRequestContext.getCurrentServletContext();
            }
        }
        HttpServerRequest applicationRequest = request;
        if (applicationRequest.getScope(Scope.APPLICATION) != null) {
            Object context = applicationRequest.getScope(Scope.APPLICATION)
                    .getAttachment(ServletContext.class.getName());
            if (context instanceof ServletContext) {
                return (ServletContext) context;
            }
        }
        return null;
    }

    static HttpServerExchange resolveExchange(HttpServerRequest request) {
        HttpExchangeSpi exchangeSpi = resolveExchangeSpi(request);
        if (!(exchangeSpi instanceof ElytronHttpExchange)) {
            return null;
        }
        try {
            Field exchangeField = ElytronHttpExchange.class.getDeclaredField("httpServerExchange");
            exchangeField.setAccessible(true);
            Object value = exchangeField.get(exchangeSpi);
            return value instanceof HttpServerExchange ? (HttpServerExchange) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static HttpExchangeSpi resolveExchangeSpi(HttpServerRequest request) {
        Class<?> type = request.getClass();
        while (type != null) {
            HttpExchangeSpi spi = readExchangeSpiField(type, request, "httpExchangeSpi");
            if (spi != null) {
                return spi;
            }
            spi = readExchangeSpiField(type, request, "exchangeSpi");
            if (spi != null) {
                return spi;
            }
            type = type.getSuperclass();
        }
        return null;
    }

    private static HttpExchangeSpi readExchangeSpiField(Class<?> type, HttpServerRequest request, String fieldName) {
        try {
            Field exchangeField = type.getDeclaredField(fieldName);
            exchangeField.setAccessible(true);
            Object value = exchangeField.get(request);
            if (value instanceof HttpExchangeSpi) {
                return (HttpExchangeSpi) value;
            }
        } catch (NoSuchFieldException ignored) {
        } catch (Exception ignored) {
        }
        return null;
    }
}
