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

/**
 * Bridges a SAML-authenticated principal into the container security subsystem using JAAS,
 * producing an Elytron {@code SecurityIdentity} (or equivalent) so servlet authorization
 * ({@code auth-constraint}, {@code isUserInRole}) works correctly.
 * <p>
 * Applications may supply their own implementation (for example one that integrates with an
 * existing JAAS-to-Elytron bridge or supports MFA) by configuring
 * {@link JaasElytronAuthenticationBridgeProvider#INIT_PARAM_BRIDGE_CLASS} in {@code web.xml}
 * or registering a {@link java.util.ServiceLoader} provider.
 * </p>
 *
 * @see PicketLinkJaasElytronAuthenticationBridge
 * @see JaasElytronAuthenticationBridgeProvider
 */
public interface JaasElytronAuthenticationBridge {

    /**
     * Perform JAAS login for the SAML user and associate the resulting identity with the
     * current request security context.
     *
     * @param context bridge invocation context
     * @return authentication outcome; {@link JaasElytronAuthenticationBridgeResult#isSuccess()} is
     *         {@code false} when the bridge could not establish container identity (caller may fall
     *         back to Undertow-only registration)
     */
    JaasElytronAuthenticationBridgeResult authenticate(JaasElytronAuthenticationBridgeContext context);
}
