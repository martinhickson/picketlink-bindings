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
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Set;
import java.util.function.Supplier;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlPrincipal;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSecurityIdentityFactory;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.cache.IdentityCache;

/**
 * Elytron {@code SecurityContextImpl} integration helpers.
 */
public final class ElytronSecurityContextSupport {

    private static final String SECURITY_CONTEXT_IMPL =
            "org.wildfly.elytron.web.undertow.server.SecurityContextImpl";
    private static final String IDENTITY_CACHE = "org.wildfly.security.cache.IdentityCache";

    private ElytronSecurityContextSupport() {
    }

    public static boolean isElytronSecurityContext(SecurityContext securityContext) {
        if (securityContext == null) {
            return false;
        }
        if (isAssignable(SECURITY_CONTEXT_IMPL, securityContext.getClass())) {
            return true;
        }
        return securityContext.getClass().getName().contains("elytron")
                && securityContext.getClass().getName().contains("SecurityContext");
    }

    public static SecurityDomain resolveSecurityDomain(SecurityContext securityContext) {
        if (!isElytronSecurityContext(securityContext)) {
            return null;
        }
        try {
            Field securityDomainField = findField(securityContext.getClass(), "securityDomain");
            if (securityDomainField == null) {
                return null;
            }
            securityDomainField.setAccessible(true);
            Object value = securityDomainField.get(securityContext);
            return value instanceof SecurityDomain ? (SecurityDomain) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    public static Principal createNamePrincipal(SecurityContext securityContext, String username) {
        return new NamePrincipal(username);
    }

    public static SecurityIdentity createSecurityIdentity(
            SecurityContext securityContext, Principal principal, Set<String> roles) {
        SecurityDomain securityDomain = resolveSecurityDomain(securityContext);
        if (securityDomain == null || principal == null) {
            return null;
        }
        if (principal instanceof PicketLinkSamlPrincipal) {
            return PicketLinkSecurityIdentityFactory.authorize(securityDomain, (PicketLinkSamlPrincipal) principal);
        }
        PicketLinkSamlPrincipal samlPrincipal = new PicketLinkSamlPrincipal(principal.getName(), roles);
        return PicketLinkSecurityIdentityFactory.authorize(securityDomain, samlPrincipal);
    }

    public static boolean completeAuthentication(
            SecurityContext securityContext, SecurityIdentity securityIdentity, String mechanism) {
        if (!isElytronSecurityContext(securityContext) || securityIdentity == null) {
            return false;
        }
        try {
            Method complete = findMethod(
                    securityContext.getClass(),
                    "authenticationComplete",
                    SecurityIdentity.class,
                    String.class);
            if (complete == null) {
                return false;
            }
            complete.setAccessible(true);
            complete.invoke(securityContext, securityIdentity, mechanism);
            cacheIdentity(securityContext, securityIdentity);
            return hasRoles(securityContext.getAuthenticatedAccount());
        } catch (Exception ignored) {
            return false;
        }
    }

    public static boolean completeAuthentication(SecurityContext securityContext, Account account, String mechanism) {
        if (account == null) {
            return false;
        }
        SecurityIdentity identity = createSecurityIdentity(securityContext, account.getPrincipal(), account.getRoles());
        if (identity == null) {
            return false;
        }
        return completeAuthentication(securityContext, identity, mechanism);
    }

    public static Account toElytronAccount(SecurityContext securityContext, SecurityIdentity securityIdentity) {
        if (securityIdentity == null) {
            return null;
        }
        try {
            ClassLoader loader = securityContext.getClass().getClassLoader();
            Class<?> accountClass = Class.forName(
                    "org.wildfly.elytron.web.undertow.server.ElytronAccount", true, loader);
            return (Account) accountClass.getConstructor(SecurityIdentity.class).newInstance(securityIdentity);
        } catch (Exception ignored) {
            return null;
        }
    }

    static Class<?> securityIdentityClass(ClassLoader loader) throws ClassNotFoundException {
        return SecurityIdentity.class;
    }

    static Class<?> securityDomainClass(ClassLoader loader) throws ClassNotFoundException {
        return SecurityDomain.class;
    }

    private static void cacheIdentity(SecurityContext securityContext, SecurityIdentity securityIdentity)
            throws Exception {
        Field cacheSupplierField = findField(securityContext.getClass(), "identityCacheSupplier");
        if (cacheSupplierField == null) {
            return;
        }
        cacheSupplierField.setAccessible(true);
        Object cacheSupplier = cacheSupplierField.get(securityContext);
        if (!(cacheSupplier instanceof Supplier<?>)) {
            return;
        }
        Object identityCache = ((Supplier<?>) cacheSupplier).get();
        if (identityCache instanceof IdentityCache) {
            ((IdentityCache) identityCache).put(securityIdentity);
        }
    }

    private static boolean hasRoles(Account account) {
        return account != null && account.getRoles() != null && !account.getRoles().isEmpty();
    }

    private static Method findMethod(Class<?> type, String name, Class<?>... parameterTypes) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredMethod(name, parameterTypes);
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }

    private static Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }

    private static boolean isAssignable(String expectedType, Class<?> actualType) {
        try {
            Class<?> expected = Class.forName(expectedType, false, actualType.getClassLoader());
            return expected.isAssignableFrom(actualType);
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
