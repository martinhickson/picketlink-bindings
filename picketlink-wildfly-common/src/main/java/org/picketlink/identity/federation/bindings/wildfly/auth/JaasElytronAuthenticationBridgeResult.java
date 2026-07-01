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

/**
 * Outcome of a {@link JaasElytronAuthenticationBridge#authenticate} invocation.
 */
public final class JaasElytronAuthenticationBridgeResult {

    private final boolean success;
    private final boolean elytronIdentityEstablished;
    private final Account account;

    private JaasElytronAuthenticationBridgeResult(boolean success, boolean elytronIdentityEstablished, Account account) {
        this.success = success;
        this.elytronIdentityEstablished = elytronIdentityEstablished;
        this.account = account;
    }

    public static JaasElytronAuthenticationBridgeResult success(Account account, boolean elytronIdentityEstablished) {
        return new JaasElytronAuthenticationBridgeResult(true, elytronIdentityEstablished, account);
    }

    public static JaasElytronAuthenticationBridgeResult failure() {
        return new JaasElytronAuthenticationBridgeResult(false, false, null);
    }

    public boolean isSuccess() {
        return success;
    }

    /**
     * {@code true} when an Elytron {@code SecurityIdentity} was associated with the request
     * (Undertow {@code Account} registration alone is not sufficient for Elytron authorization).
     */
    public boolean isElytronIdentityEstablished() {
        return elytronIdentityEstablished;
    }

    public Account getAccount() {
        return account;
    }
}
