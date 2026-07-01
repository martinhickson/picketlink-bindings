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

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismInformation;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;

/**
 * Builds {@link SecurityIdentity} instances for SAML principals with application roles attached.
 */
public final class PicketLinkSecurityIdentityFactory {

    /** Elytron custom-realm name; override with {@code -Dorg.picketlink.elytron.saml.realm=...}. */
    public static final String SAML_REALM_NAME =
            System.getProperty("org.picketlink.elytron.saml.realm", "PicketLinkSamlRealm");

    private static final String[] ROLE_REALMS = {
            "web", "servlet", "FORM", PicketLinkElytronIdentityCompletion.MECHANISM_NAME};

    private static final MechanismInformation SAML_MECHANISM_INFORMATION = new MechanismInformation() {
        @Override
        public String getMechanismType() {
            return "HTTP";
        }

        @Override
        public String getMechanismName() {
            return PicketLinkElytronIdentityCompletion.MECHANISM_NAME;
        }

        @Override
        public String getHostName() {
            return null;
        }

        @Override
        public String getProtocol() {
            return null;
        }
    };

    private PicketLinkSecurityIdentityFactory() {
    }

    public static SecurityIdentity authorize(SecurityDomain securityDomain, PicketLinkSamlPrincipal principal) {
        if (securityDomain == null || principal == null) {
            return null;
        }

        SecurityIdentity identity = authorizeViaSamlMechanism(securityDomain, principal);
        if (identity == null) {
            identity = securityDomain.createAdHocIdentity(principal);
        }
        return attachRoleMappers(identity, principal.getRoles());
    }

    public static SecurityIdentity attachRoleMappers(SecurityIdentity identity, Collection<String> roles) {
        if (identity == null) {
            return null;
        }
        Set<String> roleSet = toRoleSet(roles);
        if (roleSet.isEmpty()) {
            return identity;
        }

        Roles mappedRoles = Roles.fromSet(roleSet);
        RoleMapper roleMapper = RoleMapper.constant(mappedRoles);
        SecurityIdentity enriched = identity.withDefaultRoleMapper(roleMapper);
        for (String realm : ROLE_REALMS) {
            enriched = enriched.withRoleMapper(realm, roleMapper);
        }
        return enriched;
    }

    private static SecurityIdentity authorizeViaSamlMechanism(
            SecurityDomain securityDomain, PicketLinkSamlPrincipal principal) {
        MechanismConfiguration mechanismConfiguration = MechanismConfiguration.builder()
                .setRealmMapper(RealmMapper.matchingPrincipalType(PicketLinkSamlPrincipal.class, SAML_REALM_NAME))
                .addMechanismRealm(MechanismRealmConfiguration.builder()
                        .setRealmName(SAML_REALM_NAME)
                        .build())
                .build();

        MechanismConfigurationSelector selector = MechanismConfigurationSelector.predicateSelector(
                info -> PicketLinkElytronIdentityCompletion.MECHANISM_NAME.equals(info.getMechanismName()),
                mechanismConfiguration);

        try (ServerAuthenticationContext authenticationContext =
                securityDomain.createNewAuthenticationContext(selector)) {
            authenticationContext.setMechanismInformation(SAML_MECHANISM_INFORMATION);
            authenticationContext.setAuthenticationPrincipal(principal);
            if (!authenticationContext.exists() || !authenticationContext.authorize()) {
                return null;
            }
            authenticationContext.succeed();
            return authenticationContext.getAuthorizedIdentity();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Set<String> toRoleSet(Collection<String> roles) {
        Set<String> roleSet = new LinkedHashSet<>();
        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    roleSet.add(role);
                }
            }
        }
        return roleSet;
    }

    static Set<String> toRoleSet(List<String> roles) {
        return toRoleSet((Collection<String>) roles);
    }
}
