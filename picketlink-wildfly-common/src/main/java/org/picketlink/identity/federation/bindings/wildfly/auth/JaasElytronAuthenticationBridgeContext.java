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
import jakarta.servlet.ServletContext;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Context passed to a {@link JaasElytronAuthenticationBridge} implementation.
 */
public final class JaasElytronAuthenticationBridgeContext {

    private final HttpServerExchange httpServerExchange;
    private final SecurityContext securityContext;
    private final ServletContext servletContext;
    private final String securityDomainName;
    private final String username;
    private final List<String> roles;
    private final Principal samlPrincipal;
    private final Account undertowAccount;
    private final String jaasPassword;

    private JaasElytronAuthenticationBridgeContext(Builder builder) {
        this.httpServerExchange = builder.httpServerExchange;
        this.securityContext = builder.securityContext;
        this.servletContext = builder.servletContext;
        this.securityDomainName = builder.securityDomainName;
        this.username = builder.username;
        this.roles = builder.roles == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(builder.roles));
        this.samlPrincipal = builder.samlPrincipal;
        this.undertowAccount = builder.undertowAccount;
        this.jaasPassword = builder.jaasPassword;
    }

    public HttpServerExchange getHttpServerExchange() {
        return httpServerExchange;
    }

    public SecurityContext getSecurityContext() {
        return securityContext;
    }

    public ServletContext getServletContext() {
        return servletContext;
    }

    /**
     * Elytron application security domain name from {@code jboss-web.xml}, if configured.
     */
    public String getSecurityDomainName() {
        return securityDomainName;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public Principal getSamlPrincipal() {
        return samlPrincipal;
    }

    /**
     * Undertow account assembled by PicketLink prior to bridging; useful as a fallback.
     */
    public Account getUndertowAccount() {
        return undertowAccount;
    }

    /**
     * Password credential presented to the JAAS stack (conventionally
     * {@link org.picketlink.identity.federation.bindings.wildfly.ServiceProviderSAMLContext#EMPTY_PASSWORD}).
     */
    public String getJaasPassword() {
        return jaasPassword;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private HttpServerExchange httpServerExchange;
        private SecurityContext securityContext;
        private ServletContext servletContext;
        private String securityDomainName;
        private String username;
        private Collection<String> roles;
        private Principal samlPrincipal;
        private Account undertowAccount;
        private String jaasPassword;

        public Builder httpServerExchange(HttpServerExchange httpServerExchange) {
            this.httpServerExchange = httpServerExchange;
            return this;
        }

        public Builder securityContext(SecurityContext securityContext) {
            this.securityContext = securityContext;
            return this;
        }

        public Builder servletContext(ServletContext servletContext) {
            this.servletContext = servletContext;
            return this;
        }

        public Builder securityDomainName(String securityDomainName) {
            this.securityDomainName = securityDomainName;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder roles(Collection<String> roles) {
            this.roles = roles;
            return this;
        }

        public Builder samlPrincipal(Principal samlPrincipal) {
            this.samlPrincipal = samlPrincipal;
            return this;
        }

        public Builder undertowAccount(Account undertowAccount) {
            this.undertowAccount = undertowAccount;
            return this;
        }

        public Builder jaasPassword(String jaasPassword) {
            this.jaasPassword = jaasPassword;
            return this;
        }

        public JaasElytronAuthenticationBridgeContext build() {
            return new JaasElytronAuthenticationBridgeContext(this);
        }
    }
}
