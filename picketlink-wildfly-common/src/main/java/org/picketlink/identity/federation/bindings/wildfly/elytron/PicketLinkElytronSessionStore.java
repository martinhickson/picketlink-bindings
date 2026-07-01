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

import org.jboss.logging.Logger;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * Elytron {@link HttpScope} session storage (Keycloak {@code ElytronSamlSessionStore} pattern).
 */
public final class PicketLinkElytronSessionStore {

    public static final String SAML_REDIRECT_URI = "SAML_REDIRECT_URI";

    private static final Logger LOGGER = Logger.getLogger(PicketLinkElytronSessionStore.class);

    private final PicketLinkElytronHttpFacade facade;

    PicketLinkElytronSessionStore(PicketLinkElytronHttpFacade facade) {
        this.facade = facade;
    }

    public void saveAccount(PicketLinkSamlPrincipal principal) {
        HttpScope session = getSession(true);
        session.setAttachment(PicketLinkSamlSession.SESSION_KEY, new PicketLinkSamlSession(principal));
    }

    public PicketLinkSamlSession getAccount() {
        HttpScope session = getSession(false);
        if (!session.exists()) {
            return null;
        }
        Object attachment = session.getAttachment(PicketLinkSamlSession.SESSION_KEY);
        return attachment instanceof PicketLinkSamlSession ? (PicketLinkSamlSession) attachment : null;
    }

    /**
     * Restores a logged-in session via the Elytron callback completion path.
     */
    public boolean isLoggedIn() {
        HttpScope session = getSession(false);
        if (!session.exists()) {
            return false;
        }
        PicketLinkSamlSession samlSession = getAccount();
        if (samlSession == null) {
            return false;
        }
        LOGGER.debugf("Restoring PicketLink SAML session for [%s]", samlSession.getPrincipal().getName());
        restoreRequest();
        facade.completeAuthentication(samlSession.getPrincipal());
        return true;
    }

    public void saveRequest() {
        facade.suspendRequest();
        HttpScope session = getSession(true);
        session.setAttachment(SAML_REDIRECT_URI, facade.getRequest().getRequestURI());
    }

    public boolean restoreRequest() {
        return facade.resumeRequest();
    }

    public void logoutAccount() {
        HttpScope session = getSession(false);
        if (session.exists()) {
            session.setAttachment(PicketLinkSamlSession.SESSION_KEY, null);
            session.setAttachment(PicketLinkElytronIdentityCompletion.CACHED_IDENTITY_SESSION_KEY, null);
            session.setAttachment(SAML_REDIRECT_URI, null);
        }
    }

    private HttpScope getSession(boolean create) {
        HttpScope scope = facade.getRequest().getScope(Scope.SESSION);
        if (!scope.exists() && create) {
            scope.create();
        }
        return scope;
    }
}
