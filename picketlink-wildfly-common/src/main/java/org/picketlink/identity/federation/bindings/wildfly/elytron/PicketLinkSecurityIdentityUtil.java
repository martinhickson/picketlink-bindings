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

import java.io.IOException;
import java.security.Principal;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpAuthenticationException;

/**
 * Builds a {@link SecurityIdentity} via the Elytron callback pipeline (Keycloak adapter pattern).
 */
public final class PicketLinkSecurityIdentityUtil {

    private PicketLinkSecurityIdentityUtil() {
    }

    public static SecurityIdentity authorize(CallbackHandler callbackHandler, Principal principal) {
        if (callbackHandler == null || principal == null) {
            return null;
        }
        try {
            EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(new Evidence() {
                @Override
                public Principal getPrincipal() {
                    return principal;
                }
            });

            callbackHandler.handle(new Callback[] {evidenceVerifyCallback});

            if (!evidenceVerifyCallback.isVerified()) {
                return null;
            }

            AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);
            try {
                callbackHandler.handle(new Callback[] {authorizeCallback});
            } catch (Exception e) {
                throw new HttpAuthenticationException(e);
            }

            if (!authorizeCallback.isAuthorized()) {
                return null;
            }

            SecurityIdentityCallback securityIdentityCallback = new SecurityIdentityCallback();
            callbackHandler.handle(new Callback[] {AuthenticationCompleteCallback.SUCCEEDED, securityIdentityCallback});
            return securityIdentityCallback.getSecurityIdentity();
        } catch (UnsupportedCallbackException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
