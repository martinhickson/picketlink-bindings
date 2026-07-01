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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SAML principal carrying role attributes for Elytron {@link PicketLinkSamlSecurityRealm}.
 */
public final class PicketLinkSamlPrincipal implements Principal, Serializable {

    public static final String ROLES_ATTRIBUTE = "Roles";

    private static final long serialVersionUID = 1L;

    private final String name;
    private final Map<String, List<String>> attributes;

    public PicketLinkSamlPrincipal(String name, Iterable<String> roles) {
        this.name = name;
        Map<String, List<String>> attrs = new HashMap<>();
        List<String> roleList = new ArrayList<>();
        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    roleList.add(role);
                }
            }
        }
        attrs.put(ROLES_ATTRIBUTE, roleList);
        this.attributes = Collections.unmodifiableMap(attrs);
    }

    @Override
    public String getName() {
        return name;
    }

    public Map<String, List<String>> getAttributes() {
        return attributes;
    }

    public List<String> getRoles() {
        return attributes.getOrDefault(ROLES_ATTRIBUTE, Collections.emptyList());
    }
}
