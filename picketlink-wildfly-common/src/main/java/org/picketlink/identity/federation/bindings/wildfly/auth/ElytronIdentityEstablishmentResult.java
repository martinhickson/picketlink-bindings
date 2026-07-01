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
 * Outcome of {@link ElytronIdentityEstablishment#establish}.
 */
public final class ElytronIdentityEstablishmentResult {

    private final boolean success;
    private final boolean elytronIdentityEstablished;
    private final Account account;

    private ElytronIdentityEstablishmentResult(boolean success, boolean elytronIdentityEstablished, Account account) {
        this.success = success;
        this.elytronIdentityEstablished = elytronIdentityEstablished;
        this.account = account;
    }

    public static ElytronIdentityEstablishmentResult success(Account account, boolean elytronIdentityEstablished) {
        return new ElytronIdentityEstablishmentResult(true, elytronIdentityEstablished, account);
    }

    public static ElytronIdentityEstablishmentResult failure() {
        return new ElytronIdentityEstablishmentResult(false, false, null);
    }

    public static ElytronIdentityEstablishmentResult fromBridgeResult(JaasElytronAuthenticationBridgeResult bridgeResult) {
        if (bridgeResult == null || !bridgeResult.isSuccess()) {
            return failure();
        }
        return success(bridgeResult.getAccount(), bridgeResult.isElytronIdentityEstablished());
    }

    public boolean isSuccess() {
        return success;
    }

    public boolean isElytronIdentityEstablished() {
        return elytronIdentityEstablished;
    }

    public Account getAccount() {
        return account;
    }
}
