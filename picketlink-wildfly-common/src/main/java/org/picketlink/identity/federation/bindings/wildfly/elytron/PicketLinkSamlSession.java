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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SAML session state stored in Elytron {@code HttpScope} (Keycloak {@code SamlSession} pattern).
 */
public final class PicketLinkSamlSession implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final String SESSION_KEY = PicketLinkSamlSession.class.getName();

    private final PicketLinkSamlPrincipal principal;

    public PicketLinkSamlSession(PicketLinkSamlPrincipal principal) {
        this.principal = principal;
    }

    public PicketLinkSamlPrincipal getPrincipal() {
        return principal;
    }

    public static PicketLinkSamlSession from(String username, Iterable<String> roles) {
        return new PicketLinkSamlSession(new PicketLinkSamlPrincipal(username, roles));
    }

    public static List<String> copyRoles(Iterable<String> roles) {
        List<String> copy = new ArrayList<>();
        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    copy.add(role);
                }
            }
        }
        return Collections.unmodifiableList(copy);
    }
}
