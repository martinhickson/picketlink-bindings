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

import org.picketlink.identity.federation.core.interfaces.RoleGenerator;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.Roles;

import javax.security.auth.Subject;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Role generator for WildFly Elytron. Decoded identity roles come first, then the
 * identity attributes {@code Roles} and {@code groups}, then the JAAS Subject group
 * {@code Roles} from the JACC policy context.
 */
public class UndertowRoleGenerator implements RoleGenerator {

    private static final String SUBJECT_CONTAINER = "javax.security.auth.Subject.container";

    @Override
    public List<String> generateRoles(Principal principal) {
        if (principal instanceof PicketLinkUndertowPrincipal) {
            List<String> declared = ((PicketLinkUndertowPrincipal) principal).getRoles();
            if (declared != null && !declared.isEmpty()) {
                return Collections.unmodifiableList(new ArrayList<String>(declared));
            }
        }

        List<String> roles = new ArrayList<String>();
        addElytronRoles(roles);
        if (roles.isEmpty()) {
            addRolesGroup(roles, jaccSubject());
        }
        return Collections.unmodifiableList(roles);
    }

    private static void addElytronRoles(List<String> roles) {
        SecurityDomain domain;
        try {
            domain = SecurityDomain.getCurrent();
        } catch (RuntimeException e) {
            return;
        }
        if (domain == null) {
            return;
        }
        SecurityIdentity identity = domain.getCurrentSecurityIdentity();
        if (identity == null || identity.isAnonymous()) {
            return;
        }
        Roles decoded = identity.getRoles();
        if (decoded != null) {
            for (String role : decoded) {
                addRole(roles, role);
            }
        }
        if (!roles.isEmpty()) {
            return;
        }
        Attributes attributes = identity.getAttributes();
        if (attributes == null) {
            return;
        }
        addAttribute(roles, attributes, "Roles");
        if (roles.isEmpty()) {
            addAttribute(roles, attributes, "groups");
        }
    }

    private static void addAttribute(List<String> roles, Attributes attributes, String name) {
        if (!attributes.containsKey(name)) {
            return;
        }
        Attributes.Entry entry = attributes.get(name);
        if (entry == null) {
            return;
        }
        for (String value : entry) {
            addRole(roles, value);
        }
    }

    static void addRolesGroup(List<String> roles, Subject subject) {
        if (subject == null) {
            return;
        }
        for (Principal principal : subject.getPrincipals()) {
            if (principal == null || !"Roles".equals(principal.getName())) {
                continue;
            }
            try {
                Method members = principal.getClass().getMethod("members");
                Object value = members.invoke(principal);
                if (!(value instanceof Enumeration)) {
                    continue;
                }
                Enumeration<?> enumeration = (Enumeration<?>) value;
                while (enumeration.hasMoreElements()) {
                    Object role = enumeration.nextElement();
                    if (role instanceof Principal) {
                        addRole(roles, ((Principal) role).getName());
                    }
                }
            } catch (ReflectiveOperationException ignored) {
                // A principal named Roles that is not a JAAS group.
            }
        }
    }

    private static Subject jaccSubject() {
        for (String className : new String[] {
                "jakarta.security.jacc.PolicyContext",
                "javax.security.jacc.PolicyContext" }) {
            try {
                Class<?> type = Class.forName(className);
                Method getContext = type.getMethod("getContext", String.class);
                Object value = getContext.invoke(null, SUBJECT_CONTAINER);
                if (value instanceof Subject) {
                    return (Subject) value;
                }
            } catch (Throwable ignored) {
                // The API is absent, or this request has no container Subject.
            }
        }
        return null;
    }

    private static void addRole(List<String> roles, String role) {
        if (role != null && !role.isEmpty() && !roles.contains(role)) {
            roles.add(role);
        }
    }
}
