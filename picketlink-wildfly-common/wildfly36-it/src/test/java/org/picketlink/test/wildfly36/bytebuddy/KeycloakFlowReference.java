package org.picketlink.test.wildfly36.bytebuddy;

/**
 * Maps Keycloak WildFly Elytron SAML adapter steps to trace markers for gap analysis.
 *
 * Keycloak reference (org.keycloak.adapters.saml.elytron):
 * <pre>
 * 1. KeycloakHttpServerAuthenticationMechanism.evaluateRequest
 * 2. ElytronSamlAuthenticator.authenticate()
 * 3. ElytronSamlSessionStore.saveAccount(SamlSession) -> HttpScope.setAttachment(SamlSession)
 * 4. ElytronHttpFacade.authenticationComplete(SamlSession)
 * 5. SecurityIdentityUtil.authorize(callbackHandler, SamlPrincipal)  // Elytron callback pipeline
 * 6. request.authenticationComplete(responseConsumer, logoutHandler)   // HttpAuthenticator caches identity
 * 7. HttpAuthenticator.restoreIdentity() on next request -> CachedIdentity from session scope
 * 8. SecurityIdentity.getRoles() populated via realm AuthorizationIdentity attributes
 * </pre>
 */
public final class KeycloakFlowReference {

    public static final String KC1_MECHANISM_EVALUATE =
            "KeycloakHttpServerAuthenticationMechanism.evaluateRequest";
    public static final String KC2_AUTHENTICATOR =
            "ElytronSamlAuthenticator.authenticate -> outcome AUTHENTICATED";
    public static final String KC3_SAVE_ACCOUNT =
            "ElytronSamlSessionStore.saveAccount -> HttpScope SESSION SamlSession attachment";
    public static final String KC4_FACADE_COMPLETE =
            "ElytronHttpFacade.authenticationComplete(SamlSession)";
    public static final String KC5_CALLBACK_AUTHORIZE =
            "SecurityIdentityUtil.authorize(callbackHandler, SamlPrincipal)";
    public static final String KC6_REQUEST_COMPLETE =
            "HttpServerRequest.authenticationComplete(consumer, logoutHandler)";
    public static final String KC7_RESTORE_IDENTITY =
            "HttpAuthenticator.restoreIdentity -> CachedIdentity from session HttpScope";
    public static final String KC8_ROLES =
            "SecurityIdentity.getRoles() from realm AuthorizationIdentity (non-empty)";

    private KeycloakFlowReference() {
    }
}
