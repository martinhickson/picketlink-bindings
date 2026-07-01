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

import javax.security.auth.callback.CallbackHandler;
import org.jboss.logging.Logger;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;

/**
 * Elytron HTTP authentication mechanism for PicketLink SAML SP (Keycloak adapter pattern).
 *
 * <p>The {@code direct} identity strategy runs the full SAML flow here via
 * {@link PicketLinkElytronSamlAuthenticator}. The {@code jaas-bridge} strategy may still delegate to the
 * Undertow {@code SPFormAuthenticationMechanism} when needed.</p>
 */
public class PicketLinkSamlHttpServerAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    public static final String NAME = PicketLinkElytronIdentityCompletion.MECHANISM_NAME;

    private static final Logger LOGGER = Logger.getLogger(PicketLinkSamlHttpServerAuthenticationMechanism.class);

    private final CallbackHandler callbackHandler;

    public PicketLinkSamlHttpServerAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        LOGGER.debugf("Evaluating request for path [%s]", request.getRequestURI());

        PicketLinkElytronHttpFacade facade = new PicketLinkElytronHttpFacade(request, callbackHandler);
        if (!facade.hasDeploymentContext()) {
            LOGGER.debugf("Ignoring request [%s]; no PicketLink SP deployment context.", request.getRequestURI());
            request.noAuthenticationInProgress();
            return;
        }

        if (facade.isJaasBridgePath()) {
            evaluateJaasBridgePath(facade, request);
            return;
        }

        PicketLinkElytronAuthOutcome outcome = PicketLinkElytronSamlAuthenticator.authenticate(facade);
        completeOutcome(facade, outcome);
    }

    private void evaluateJaasBridgePath(PicketLinkElytronHttpFacade facade, HttpServerRequest request) {
        if (PicketLinkElytronUndertowBridge.shouldDelegate(request)
                && PicketLinkElytronUndertowBridge.delegateAuthenticate(request)) {
            return;
        }
        PicketLinkSamlSession session = PicketLinkElytronIdentityCompletion.readSession(request);
        if (session == null) {
            request.noAuthenticationInProgress();
            return;
        }
        org.wildfly.security.auth.server.SecurityIdentity identity =
                PicketLinkElytronIdentityCompletion.authorizeFromSession(request, callbackHandler, null);
        if (identity != null) {
            PicketLinkElytronIdentityCompletion.storeSession(request, session.getPrincipal(), identity);
            request.authenticationComplete();
        } else {
            request.noAuthenticationInProgress();
        }
    }

    private void completeOutcome(PicketLinkElytronHttpFacade facade, PicketLinkElytronAuthOutcome outcome) {
        switch (outcome) {
            case AUTHENTICATED:
                PicketLinkElytronSamlAuthenticator.completeDeferredAuthentication(facade);
                return;
            case NOT_AUTHENTICATED:
                facade.noAuthenticationInProgress();
                return;
            case AUTHENTICATION_IN_PROGRESS:
                facade.authenticationInProgress();
                return;
            case FAILED:
                facade.authenticationFailed();
                return;
            default:
                facade.noAuthenticationInProgress();
        }
    }
}
