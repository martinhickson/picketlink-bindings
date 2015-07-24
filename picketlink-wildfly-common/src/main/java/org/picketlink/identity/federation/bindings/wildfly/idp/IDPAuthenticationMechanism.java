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
package org.picketlink.identity.federation.bindings.wildfly.idp;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.impl.ClientCertAuthenticationMechanism;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.handlers.security.ServletFormAuthenticationMechanism;
import java.security.Principal;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author pedroigor
 */
public class IDPAuthenticationMechanism extends ServletFormAuthenticationMechanism {

    private final PicketLinkType configuration;
    private final ClientCertAuthenticationMechanism clientCertAuthMech;

    public IDPAuthenticationMechanism(FormParserFactory formParserFactory, String mechanismName, String loginPage, String errorPage, PicketLinkType configuration, PicketLinkAuditHelper auditHelper) {
        super(formParserFactory, mechanismName, loginPage, errorPage);
        this.configuration = configuration;
        this.clientCertAuthMech = new ClientCertAuthenticationMechanism(true);
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        IDPType idpType = (IDPType) this.configuration.getIdpOrSP();
        AuthenticationMechanismOutcome outcome = null;

        if (idpType.isSSLClientAuthentication()) {
            outcome = this.clientCertAuthMech.authenticate(exchange, securityContext);
        }

        if (outcome == null || !AuthenticationMechanismOutcome.AUTHENTICATED.equals(outcome)) {
            outcome = super.authenticate(exchange, securityContext);
        }

        return outcome;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        Principal principal = request.getUserPrincipal();

        if (isAjaxRequest(request) && principal == null) {
            return new ChallengeResult(false, HttpServletResponse.SC_FORBIDDEN);
        }

        return super.sendChallenge(exchange, securityContext);
    }

    private boolean isAjaxRequest(HttpServletRequest request) {
        String requestedWithHeader = request.getHeader(GeneralConstants.HTTP_HEADER_X_REQUESTED_WITH);
        return requestedWithHeader != null && "XMLHttpRequest".equalsIgnoreCase(requestedWithHeader);
    }
}
