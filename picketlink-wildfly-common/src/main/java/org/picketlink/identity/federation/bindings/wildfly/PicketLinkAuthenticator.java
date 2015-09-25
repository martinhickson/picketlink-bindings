/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.bindings.wildfly;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction;

import javax.security.auth.Subject;

/**
 * An authenticator that delegates actual authentication to a realm, and in turn to a security manager, by presenting a
 * "conventional" identity. The security manager must accept the conventional identity and generate the real identity for the
 * authenticated principal.
 *
 * @author <a href="mailto:ovidiu@novaordis.com">Ovidiu Feodorov</a>
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 * @since Apr 11, 2011
 */
public class PicketLinkAuthenticator implements AuthenticationMechanism {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    static final String AUTH_METHOD_NAME = "SECURITY_DOMAIN";

    /**
     * The authenticator may not be aware of the user name until after the underlying security exercise is complete. The Subject
     * will have the proper user name. Hence we may need to perform an additional authentication now with the user name we have
     * obtained.
     */
    private final boolean needSubjectPrincipalSubstitution;
    private final String subjectInteractionClassName;
    private final IdentityManager identityManager;
    private final String securityDomain;
    private SubjectSecurityInteraction subjectInteraction = null;

    public PicketLinkAuthenticator(IdentityManager identityManager, Boolean needSubjectPrincipalSubstitution, String subjectInteractionClassName, final String securityDomain) {
        this.identityManager = identityManager;
        this.needSubjectPrincipalSubstitution = needSubjectPrincipalSubstitution;
        this.subjectInteractionClassName = subjectInteractionClassName;
        this.securityDomain = securityDomain;
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        if (performAuthentication(securityContext)) {
            return AuthenticationMechanismOutcome.AUTHENTICATED;
        }

        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return null;
    }

    /**
     * <p>Actually performs the authentication. Subclasses should call this method when implementing the <code>AuthenticatorBase.authenticate</code> method.</p>
     * <p>This method was created to allow different signatures for the <code>AuthenticatorBase.authenticate</code> method according with the catalina version.</p>
     *
     * @param request
     * @param response
     * @param loginConfig
     * @return
     * @throws IOException
     */
    protected boolean performAuthentication(SecurityContext securityContext) {
        logger.trace("Authenticating user");

        Account account = securityContext.getAuthenticatedAccount();

        if (account != null) {
            logger.trace("Already authenticated '" + account.getPrincipal().getName() + "'");
            return true;
        }

        String userName = UUID.randomUUID().toString();
        String password = userName;

        account = this.identityManager.verify(userName, new PasswordCredential(password.toCharArray()));

        Account originalPrincipal = account;

        if (account != null) {
            if (needSubjectPrincipalSubstitution) {
                Principal principal = getSubjectPrincipal();
                if (principal == null)
                    throw new RuntimeException("Principal from subject is null");
                account = this.identityManager.verify(principal.getName(), new PasswordCredential(password.toCharArray()));
            }
            securityContext.authenticationComplete(account, AUTH_METHOD_NAME, false);
            if (originalPrincipal != null && needSubjectPrincipalSubstitution) {
                subjectInteraction.cleanup(originalPrincipal.getPrincipal());
            }
            return true;
        }

        return false;
    }

    protected Principal getSubjectPrincipal() {
        if (subjectInteraction == null) {
            Class<?> clazz = loadClass(getClass(), subjectInteractionClassName);
            try {
                subjectInteraction = (SubjectSecurityInteraction) clazz.newInstance();
                subjectInteraction.setSecurityDomain(this.securityDomain);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        Subject subject = subjectInteraction.get();
        if (subject != null) {
            Set<Principal> principals = subject.getPrincipals();
            if (!principals.isEmpty()) {
                return subject.getPrincipals().iterator().next();
            }
        }
        return null;
    }

    Class<?> loadClass(final Class<?> theClass, final String fqn) {
        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
            public Class<?> run() {
                ClassLoader classLoader = theClass.getClassLoader();
                Class<?> clazz = loadClass(classLoader, fqn);
                if (clazz == null) {
                    classLoader = Thread.currentThread().getContextClassLoader();
                    clazz = loadClass(classLoader, fqn);
                }
                return clazz;
            }
        });
    }

    Class<?> loadClass(final ClassLoader cl, final String fqn) {
        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
            public Class<?> run() {
                try {
                    return cl.loadClass(fqn);
                } catch (ClassNotFoundException e) {
                }
                return null;
            }
        });
    }

    public static class Factory implements AuthenticationMechanismFactory {

        private final IdentityManager identityManager;

        public Factory(final IdentityManager manager) {
            this.identityManager = manager;
        }

        @Override
        public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
            Boolean needSubjectPrincipalSubstitution = Boolean.valueOf(properties.getOrDefault("need-subject-principal-substitution", "true"));
            String subjectInteractionClassName = properties.getOrDefault("subject-interaction-class-name", "org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkJBossSubjectInteraction");
            String securityDomain = properties.get("security-domain");
            return new PicketLinkAuthenticator(this.identityManager, needSubjectPrincipalSubstitution, subjectInteractionClassName, securityDomain);
        }
    }
}