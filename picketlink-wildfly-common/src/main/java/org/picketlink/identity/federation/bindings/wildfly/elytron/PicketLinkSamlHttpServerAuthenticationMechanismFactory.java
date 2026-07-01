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

import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * ServiceLoader factory for {@link PicketLinkSamlHttpServerAuthenticationMechanism}.
 */
public class PicketLinkSamlHttpServerAuthenticationMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return new String[] {PicketLinkSamlHttpServerAuthenticationMechanism.NAME};
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(
            String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler)
            throws HttpAuthenticationException {
        if (PicketLinkSamlHttpServerAuthenticationMechanism.NAME.equals(mechanismName)) {
            return new PicketLinkSamlHttpServerAuthenticationMechanism(callbackHandler);
        }
        return null;
    }
}
