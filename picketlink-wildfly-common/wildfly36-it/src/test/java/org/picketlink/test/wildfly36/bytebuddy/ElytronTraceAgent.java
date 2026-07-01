package org.picketlink.test.wildfly36.bytebuddy;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.nio.file.Path;

/**
 * Java agent tracing Elytron SAML auth flow with Keycloak parity markers ([KC-GAP]).
 */
public final class ElytronTraceAgent {

    private ElytronTraceAgent() {
    }

    public static void premain(String agentArgs, Instrumentation instrumentation) throws Exception {
        Path helperJar = ElytronTraceBootstrap.createHelperJar();
        System.err.println("[elytron-trace] Agent starting, helper jar=" + helperJar);

        AgentBuilder.Listener listener = new AgentBuilder.Listener.Adapter() {
            @Override
            public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader,
                    JavaModule module, boolean loaded, DynamicType dynamicType) {
                System.err.println("[elytron-trace] Instrumented " + typeDescription.getName()
                        + " loader=" + classLoader);
            }

            @Override
            public void onError(String typeName, ClassLoader classLoader, JavaModule module,
                    boolean loaded, Throwable throwable) {
                System.err.println("[elytron-trace] ERROR instrumenting " + typeName + ": " + throwable);
            }
        };

        new AgentBuilder.Default()
                .with(listener)
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy."))
                .ignore(ElementMatchers.nameStartsWith("org.picketlink.test.wildfly36.bytebuddy."))
                .with(new AgentBuilder.InjectionStrategy.UsingInstrumentation(instrumentation, helperJar.toFile()))
                // Core Elytron servlet auth path
                .type(ElementMatchers.named("org.wildfly.elytron.web.undertow.server.SecurityContextImpl"))
                .transform((builder, td, cl, m, pd) ->
                        builder.method(ElementMatchers.named("authenticate"))
                                .intercept(Advice.to(ElytronTraceAdvice.Authenticate.class)))
                .type(ElementMatchers.named("org.wildfly.security.http.HttpAuthenticator"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("authenticate"))
                                .intercept(Advice.to(ElytronTraceAdvice.Authenticate.class))
                                .method(ElementMatchers.named("restoreIdentity"))
                                .intercept(Advice.to(ElytronTraceAdvice.RestoreIdentity.class)))
                .type(ElementMatchers.named("org.wildfly.elytron.web.undertow.server.servlet.ElytronAccount"))
                .transform((builder, td, cl, m, pd) ->
                        builder.method(ElementMatchers.named("getRoles"))
                                .intercept(Advice.to(ElytronTraceAdvice.GetRoles.class)))
                .type(ElementMatchers.named("org.wildfly.security.http.HttpAuthenticator$AuthenticationExchange"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("authenticationComplete"))
                                .intercept(Advice.to(ElytronTraceAdvice.AuthenticationComplete.class))
                                .method(ElementMatchers.named("noAuthenticationInProgress"))
                                .intercept(Advice.to(ElytronTraceAdvice.NoAuthenticationInProgress.class))
                                .method(ElementMatchers.named("authenticationInProgress"))
                                .intercept(Advice.to(ElytronTraceAdvice.AuthenticationInProgress.class)))
                .type(ElementMatchers.named("org.wildfly.security.cache.CachedIdentity"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.isConstructor())
                                .intercept(Advice.to(ElytronTraceAdvice.CachedIdentityCtor.class))
                                .method(ElementMatchers.named("getSecurityIdentity"))
                                .intercept(Advice.to(ElytronTraceAdvice.CachedIdentityAccess.class))
                                .method(ElementMatchers.named("getMechanismName"))
                                .intercept(Advice.to(ElytronTraceAdvice.CachedIdentityAccess.class)))
                .type(ElementMatchers.named("org.wildfly.security.cache.IdentityCache"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("putIdentity"))
                                .intercept(Advice.to(ElytronTraceAdvice.IdentityCacheAccess.class))
                                .method(ElementMatchers.named("getIdentity"))
                                .intercept(Advice.to(ElytronTraceAdvice.IdentityCacheAccess.class)))
                .type(ElementMatchers.named("org.wildfly.elytron.web.undertow.server.FormAuthenticationMechanism"))
                .transform((builder, td, cl, m, pd) ->
                        builder.method(ElementMatchers.named("evaluateRequest"))
                                .intercept(Advice.to(ElytronTraceAdvice.HttpMechanismEvaluate.class)))
                // PicketLink Elytron SAML mechanism + bridge
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSamlHttpServerAuthenticationMechanism"))
                .transform((builder, td, cl, m, pd) ->
                        builder.method(ElementMatchers.named("evaluateRequest"))
                                .intercept(Advice.to(ElytronTraceAdvice.HttpMechanismEvaluate.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkElytronUndertowBridge"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("shouldDelegate"))
                                .intercept(Advice.to(ElytronTraceAdvice.BridgeDelegate.class))
                                .method(ElementMatchers.named("delegateAuthenticate"))
                                .intercept(Advice.to(ElytronTraceAdvice.BridgeDelegate.class))
                                .method(ElementMatchers.nameContains("completeDelegatedAuthentication"))
                                .intercept(Advice.to(ElytronTraceAdvice.BridgeDelegate.class))
                                .method(ElementMatchers.nameContains("readSavedAccountRoles"))
                                .intercept(Advice.to(ElytronTraceAdvice.BridgeDelegate.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkElytronIdentityCompletion"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("storeSession"))
                                .intercept(Advice.to(ElytronTraceAdvice.SessionIdentitySupport.class))
                                .method(ElementMatchers.named("authorizeFromSession"))
                                .intercept(Advice.to(ElytronTraceAdvice.IdentityCompletion.class))
                                .method(ElementMatchers.named("complete"))
                                .intercept(Advice.to(ElytronTraceAdvice.IdentityCompletion.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSecurityIdentityUtil"))
                .transform((builder, td, cl, m, pd) ->
                        builder.method(ElementMatchers.named("authorize"))
                                .intercept(Advice.to(ElytronTraceAdvice.SecurityIdentityUtilAuthorize.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.elytron.PicketLinkSecurityIdentityFactory"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("authorize"))
                                .intercept(Advice.to(ElytronTraceAdvice.SecurityIdentityUtilAuthorize.class))
                                .method(ElementMatchers.named("attachRoleMappers"))
                                .intercept(Advice.to(ElytronTraceAdvice.SecurityIdentityUtilAuthorize.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSessionIdentitySupport"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("store"))
                                .intercept(Advice.to(ElytronTraceAdvice.SessionIdentitySupport.class))
                                .method(ElementMatchers.named("restore"))
                                .intercept(Advice.to(ElytronTraceAdvice.SessionIdentitySupportWithReturn.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.auth.ElytronSecurityContextSupport"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("completeAuthentication"))
                                .intercept(Advice.to(ElytronTraceAdvice.SessionIdentitySupportWithReturn.class))
                                .method(ElementMatchers.named("createSecurityIdentity"))
                                .intercept(Advice.to(ElytronTraceAdvice.SecurityIdentityUtilAuthorize.class)))
                .type(ElementMatchers.named(
                        "org.picketlink.identity.federation.bindings.wildfly.sp.SPFormAuthenticationMechanism"))
                .transform((builder, td, cl, m, pd) ->
                        builder
                                .method(ElementMatchers.named("authenticate"))
                                .intercept(Advice.to(ElytronTraceAdvice.SpMechanismAuthenticate.class))
                                .method(ElementMatchers.named("register"))
                                .intercept(Advice.to(ElytronTraceAdvice.Register.class))
                                .method(ElementMatchers.named("isUserInRole"))
                                .intercept(Advice.to(ElytronTraceAdvice.AuthorizationPermit.class)))
                .installOn(instrumentation);

        System.err.println("[elytron-trace] Agent installed (auth hot-path). Keycloak gaps logged as [KC-GAP]");
    }
}
