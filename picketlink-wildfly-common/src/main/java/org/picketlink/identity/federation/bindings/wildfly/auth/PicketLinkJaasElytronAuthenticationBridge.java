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

import io.undertow.security.idm.Account;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.apache.cxf.common.security.GroupPrincipal;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.bindings.wildfly.ServiceProviderSAMLContext;
import org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkElytronIdentityCompletion;

/**
 * JAAS bridge implementation used when {@link ElytronIdentityEstablishmentProvider#STRATEGY_JAAS_BRIDGE}
 * is selected, or when configured explicitly via {@link JaasElytronAuthenticationBridgeProvider}.
 */
public class PicketLinkJaasElytronAuthenticationBridge implements JaasElytronAuthenticationBridge {

    public static final String INIT_PARAM_JAAS_ENTRY = "org.picketlink.jaas.login.entry";

    public static final String DEFAULT_JAAS_ENTRY = "PicketLinkSP";

    private static final PicketLinkLogger LOGGER = PicketLinkLoggerFactory.getLogger();

    @Override
    public JaasElytronAuthenticationBridgeResult authenticate(JaasElytronAuthenticationBridgeContext context) {
        if (context.getUsername() == null || context.getSecurityContext() == null) {
            return JaasElytronAuthenticationBridgeResult.failure();
        }

        if (!ElytronSecurityContextSupport.isElytronSecurityContext(context.getSecurityContext())) {
            LOGGER.trace("Elytron SecurityContext not in use; skipping JAAS/Elytron bridge.");
            return JaasElytronAuthenticationBridgeResult.failure();
        }

        String jaasEntry = resolveJaasEntry(context);
        ServiceProviderSAMLContext.push(context.getUsername(), context.getRoles());
        try {
            Subject subject = new Subject();
            Configuration jaasConfiguration = createJaasConfiguration(jaasEntry);
            LoginContext loginContext = new LoginContext(
                    jaasEntry, subject, new ServiceProviderSAMLCallbackHandler(), jaasConfiguration);
            loginContext.login();

            Principal principal = resolveCallerPrincipal(subject, context.getUsername());
            Set<String> roles = resolveRoles(subject, context.getRoles());

            JaasElytronAuthenticationBridgeContext completionContext = JaasElytronAuthenticationBridgeContext.builder()
                    .httpServerExchange(context.getHttpServerExchange())
                    .securityContext(context.getSecurityContext())
                    .servletContext(context.getServletContext())
                    .securityDomainName(context.getSecurityDomainName())
                    .username(principal.getName())
                    .roles(roles)
                    .samlPrincipal(principal)
                    .undertowAccount(context.getUndertowAccount())
                    .build();

            ElytronIdentityEstablishmentResult completion =
                    PicketLinkElytronIdentityCompletion.complete(completionContext);
            if (completion.isSuccess() && completion.isElytronIdentityEstablished()) {
                Account account = completion.getAccount();
                if (account == null) {
                    account = context.getUndertowAccount();
                }
                return JaasElytronAuthenticationBridgeResult.success(account, true);
            }
            return JaasElytronAuthenticationBridgeResult.failure();
        } catch (LoginException e) {
            LOGGER.trace("JAAS login failed for SAML user " + context.getUsername(), e);
            return JaasElytronAuthenticationBridgeResult.failure();
        } catch (Exception e) {
            LOGGER.trace("JAAS/Elytron bridge authentication failed.", e);
            return JaasElytronAuthenticationBridgeResult.failure();
        } finally {
            ServiceProviderSAMLContext.clear();
        }
    }

    private static String resolveJaasEntry(JaasElytronAuthenticationBridgeContext context) {
        if (context.getServletContext() != null) {
            String configured = context.getServletContext().getInitParameter(INIT_PARAM_JAAS_ENTRY);
            if (configured != null && !configured.isBlank()) {
                return configured.trim();
            }
        }
        return DEFAULT_JAAS_ENTRY;
    }

    private static Configuration createJaasConfiguration(final String jaasEntry) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if (!jaasEntry.equals(name)) {
                    return null;
                }
                return new AppConfigurationEntry[] {
                    new AppConfigurationEntry(
                            "org.picketlink.identity.federation.bindings.wildfly.SAML2LoginModule",
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            Map.of())
                };
            }
        };
    }

    private static Principal resolveCallerPrincipal(Subject subject, String fallbackUsername) throws Exception {
        for (Principal principal : subject.getPrincipals()) {
            if (!(principal instanceof GroupPrincipal)) {
                return principal;
            }
        }
        Class<?> namePrincipalClass = Class.forName("org.wildfly.security.auth.principal.NamePrincipal");
        return (Principal) namePrincipalClass.getConstructor(String.class).newInstance(fallbackUsername);
    }

    private static Set<String> resolveRoles(Subject subject, List<String> fallbackRoles) {
        Set<String> roles = new HashSet<>();
        for (Principal principal : subject.getPrincipals()) {
            if (principal instanceof GroupPrincipal) {
                GroupPrincipal group = (GroupPrincipal) principal;
                if ("Roles".equals(group.getName())) {
                    for (Principal role : toList(group.members())) {
                        roles.add(role.getName());
                    }
                }
            }
        }
        if (roles.isEmpty() && fallbackRoles != null) {
            roles.addAll(fallbackRoles);
        }
        return roles;
    }

    private static List<Principal> toList(Enumeration<? extends Principal> enumeration) {
        List<Principal> list = new ArrayList<>();
        while (enumeration.hasMoreElements()) {
            list.add(enumeration.nextElement());
        }
        return list;
    }
}
