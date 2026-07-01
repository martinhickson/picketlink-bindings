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

import jakarta.servlet.ServletContext;

/**
 * Delegates to a {@link JaasElytronAuthenticationBridge} (JAAS {@link javax.security.auth.login.LoginContext}
 * plus Elytron association). Use when integrating an existing JAAS-to-Elytron adapter or MFA stack.
 */
public class JaasBridgeElytronIdentityEstablishment implements ElytronIdentityEstablishment {

    private final JaasElytronAuthenticationBridge bridge;

    public JaasBridgeElytronIdentityEstablishment(JaasElytronAuthenticationBridge bridge) {
        this.bridge = bridge;
    }

    @Override
    public ElytronIdentityEstablishmentResult establish(JaasElytronAuthenticationBridgeContext context) {
        if (bridge == null) {
            return ElytronIdentityEstablishmentResult.failure();
        }
        return ElytronIdentityEstablishmentResult.fromBridgeResult(bridge.authenticate(context));
    }

    public static JaasBridgeElytronIdentityEstablishment resolve(ServletContext servletContext, String bridgeClassName) {
        JaasElytronAuthenticationBridge bridge;
        if (bridgeClassName != null && !bridgeClassName.isBlank()
                && !JaasElytronAuthenticationBridgeProvider.DISABLED.equalsIgnoreCase(bridgeClassName.trim())) {
            bridge = JaasElytronAuthenticationBridgeProvider.resolveWithClassName(bridgeClassName.trim());
        } else {
            bridge = JaasElytronAuthenticationBridgeProvider.resolve(servletContext);
        }
        return bridge != null ? new JaasBridgeElytronIdentityEstablishment(bridge) : null;
    }
}
