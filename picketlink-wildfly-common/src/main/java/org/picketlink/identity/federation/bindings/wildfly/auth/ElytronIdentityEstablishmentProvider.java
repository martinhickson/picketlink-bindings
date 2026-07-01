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
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Resolves the {@link ElytronIdentityEstablishment} strategy for a deployment.
 * <p>
 * Resolution order:
 * <ol>
 *   <li>{@code web.xml} {@value #INIT_PARAM_STRATEGY} or {@value #INIT_PARAM_STRATEGY_CLASS}</li>
 *   <li>System properties {@value #SYSTEM_PROPERTY_STRATEGY} / {@value #SYSTEM_PROPERTY_STRATEGY_CLASS}</li>
 *   <li>{@link ServiceLoader} for {@link ElytronIdentityEstablishment}</li>
 *   <li>{@link DirectElytronIdentityEstablishment} (default)</li>
 * </ol>
 * Built-in strategy names for {@value #INIT_PARAM_STRATEGY}:
 * <ul>
 *   <li>{@value #STRATEGY_DIRECT} — map SAML principal/roles directly to Elytron (default)</li>
 *   <li>{@value #STRATEGY_JAAS_BRIDGE} — JAAS {@link JaasElytronAuthenticationBridge} path</li>
 *   <li>{@value #DISABLED} — skip Elytron establishment (Undertow-only fallback)</li>
 * </ul>
 * </p>
 */
public final class ElytronIdentityEstablishmentProvider {

    public static final String INIT_PARAM_STRATEGY = "org.picketlink.elytron.identity.strategy";

    public static final String INIT_PARAM_STRATEGY_CLASS = "org.picketlink.elytron.identity.strategy.class";

    public static final String SYSTEM_PROPERTY_STRATEGY = "org.picketlink.elytron.identity.strategy";

    public static final String SYSTEM_PROPERTY_STRATEGY_CLASS = "org.picketlink.elytron.identity.strategy.class";

    public static final String STRATEGY_DIRECT = "direct";

    public static final String STRATEGY_JAAS_BRIDGE = "jaas-bridge";

    public static final String DISABLED = "none";

    public static final String DEFAULT_STRATEGY_CLASS =
            "org.picketlink.identity.federation.bindings.wildfly.auth.DirectElytronIdentityEstablishment";

    private ElytronIdentityEstablishmentProvider() {
    }

    public static ElytronIdentityEstablishment resolve(ServletContext servletContext) {
        return resolve(servletContext, null);
    }

    public static ElytronIdentityEstablishment resolve(ServletContext servletContext, String bridgeClassNameOverride) {
        String strategyClass = configuredStrategyClass(servletContext);
        if (strategyClass != null && !strategyClass.isBlank()) {
            if (DISABLED.equalsIgnoreCase(strategyClass.trim())) {
                return null;
            }
            return instantiate(strategyClass.trim());
        }

        String strategy = configuredStrategy(servletContext);
        if (strategy != null && DISABLED.equalsIgnoreCase(strategy.trim())) {
            return null;
        }
        if (strategy == null || strategy.isBlank() || STRATEGY_DIRECT.equalsIgnoreCase(strategy.trim())) {
            return new DirectElytronIdentityEstablishment();
        }
        if (STRATEGY_JAAS_BRIDGE.equalsIgnoreCase(strategy.trim())) {
            JaasBridgeElytronIdentityEstablishment bridgeStrategy =
                    JaasBridgeElytronIdentityEstablishment.resolve(servletContext, bridgeClassNameOverride);
            return bridgeStrategy != null ? bridgeStrategy : new DirectElytronIdentityEstablishment();
        }

        Iterator<ElytronIdentityEstablishment> discovered =
                ServiceLoader.load(ElytronIdentityEstablishment.class).iterator();
        if (discovered.hasNext()) {
            return discovered.next();
        }

        return new DirectElytronIdentityEstablishment();
    }

    public static ElytronIdentityEstablishment resolveWithClassName(String className) {
        if (className == null || className.isBlank() || DISABLED.equalsIgnoreCase(className.trim())) {
            return null;
        }
        return instantiate(className.trim());
    }

    private static String configuredStrategy(ServletContext servletContext) {
        String strategy = servletContext != null ? servletContext.getInitParameter(INIT_PARAM_STRATEGY) : null;
        if (strategy == null || strategy.isBlank()) {
            strategy = System.getProperty(SYSTEM_PROPERTY_STRATEGY);
        }
        return strategy;
    }

    private static String configuredStrategyClass(ServletContext servletContext) {
        String strategyClass = servletContext != null ? servletContext.getInitParameter(INIT_PARAM_STRATEGY_CLASS) : null;
        if (strategyClass == null || strategyClass.isBlank()) {
            strategyClass = System.getProperty(SYSTEM_PROPERTY_STRATEGY_CLASS);
        }
        return strategyClass;
    }

    private static ElytronIdentityEstablishment instantiate(final String className) {
        return AccessController.doPrivileged((PrivilegedAction<ElytronIdentityEstablishment>) () -> {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            if (loader == null) {
                loader = ElytronIdentityEstablishmentProvider.class.getClassLoader();
            }
            try {
                Class<?> clazz = Class.forName(className, true, loader);
                return ElytronIdentityEstablishment.class.cast(clazz.getDeclaredConstructor().newInstance());
            } catch (Exception e) {
                throw new IllegalStateException("Unable to instantiate Elytron identity strategy: " + className, e);
            }
        });
    }
}
