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
 * Resolves the {@link JaasElytronAuthenticationBridge} implementation for a deployment.
 * <p>
 * Resolution order:
 * <ol>
 *   <li>{@code web.xml} context parameter {@value #INIT_PARAM_BRIDGE_CLASS} (use {@value #DISABLED}
 *       to skip bridging)</li>
 *   <li>System property {@value #SYSTEM_PROPERTY_BRIDGE_CLASS}</li>
 *   <li>{@link ServiceLoader} discovery</li>
 *   <li>JNDI ({@value #INIT_PARAM_BRIDGE_JNDI}, default {@value #DEFAULT_BRIDGE_JNDI})</li>
 *   <li>{@link PicketLinkJaasElytronAuthenticationBridge}</li>
 * </ol>
 * </p>
 */
public final class JaasElytronAuthenticationBridgeProvider {

    public static final String INIT_PARAM_BRIDGE_CLASS = "org.picketlink.jaas.elytron.bridge.class";

    public static final String SYSTEM_PROPERTY_BRIDGE_CLASS = "org.picketlink.jaas.elytron.bridge.class";

    public static final String INIT_PARAM_BRIDGE_JNDI = "org.picketlink.jaas.elytron.bridge.jndi";

    public static final String SYSTEM_PROPERTY_BRIDGE_JNDI = "org.picketlink.jaas.elytron.bridge.jndi";

    /** Default JNDI name for a module-installed custom bridge (optional). */
    public static final String DEFAULT_BRIDGE_JNDI = "java:global/picketlink/JaasElytronBridge";

    public static final String DISABLED = "none";

    public static final String DEFAULT_BRIDGE_CLASS =
            "org.picketlink.identity.federation.bindings.wildfly.auth.PicketLinkJaasElytronAuthenticationBridge";

    private JaasElytronAuthenticationBridgeProvider() {
    }

    public static JaasElytronAuthenticationBridge resolve(ServletContext servletContext) {
        String configuredClass = null;
        if (servletContext != null) {
            configuredClass = servletContext.getInitParameter(INIT_PARAM_BRIDGE_CLASS);
        }
        if (configuredClass == null || configuredClass.isBlank()) {
            configuredClass = System.getProperty(SYSTEM_PROPERTY_BRIDGE_CLASS);
        }
        if (configuredClass != null && DISABLED.equalsIgnoreCase(configuredClass.trim())) {
            return null;
        }
        if (configuredClass != null && !configuredClass.isBlank()) {
            return instantiate(configuredClass.trim());
        }
        Iterator<JaasElytronAuthenticationBridge> discovered = ServiceLoader.load(JaasElytronAuthenticationBridge.class).iterator();
        if (discovered.hasNext()) {
            return discovered.next();
        }
        JaasElytronAuthenticationBridge fromJndi = lookupFromJndi(servletContext);
        if (fromJndi != null) {
            return fromJndi;
        }
        return instantiate(DEFAULT_BRIDGE_CLASS);
    }

    private static JaasElytronAuthenticationBridge lookupFromJndi(ServletContext servletContext) {
        String jndiName = null;
        if (servletContext != null) {
            jndiName = servletContext.getInitParameter(INIT_PARAM_BRIDGE_JNDI);
        }
        if (jndiName == null || jndiName.isBlank()) {
            jndiName = System.getProperty(SYSTEM_PROPERTY_BRIDGE_JNDI, DEFAULT_BRIDGE_JNDI);
        }
        if (jndiName == null || jndiName.isBlank() || DISABLED.equalsIgnoreCase(jndiName.trim())) {
            return null;
        }
        final String lookupName = jndiName.trim();
        return AccessController.doPrivileged((PrivilegedAction<JaasElytronAuthenticationBridge>) () -> {
            try {
                Object value = new javax.naming.InitialContext().lookup(lookupName);
                if (value instanceof JaasElytronAuthenticationBridge) {
                    return (JaasElytronAuthenticationBridge) value;
                }
            } catch (Exception ignored) {
            }
            return null;
        });
    }

    public static JaasElytronAuthenticationBridge resolveWithClassName(String className) {
        if (className == null || className.isBlank() || DISABLED.equalsIgnoreCase(className.trim())) {
            return null;
        }
        return instantiate(className.trim());
    }

    private static JaasElytronAuthenticationBridge instantiate(final String className) {
        return AccessController.doPrivileged(new PrivilegedAction<JaasElytronAuthenticationBridge>() {
            @Override
            public JaasElytronAuthenticationBridge run() {
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                if (loader == null) {
                    loader = JaasElytronAuthenticationBridgeProvider.class.getClassLoader();
                }
                try {
                    Class<?> clazz = Class.forName(className, true, loader);
                    return JaasElytronAuthenticationBridge.class.cast(clazz.getDeclaredConstructor().newInstance());
                } catch (Exception e) {
                    throw new IllegalStateException("Unable to instantiate JAAS/Elytron bridge: " + className, e);
                }
            }
        });
    }
}
