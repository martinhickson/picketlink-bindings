package org.picketlink.test.wildfly36.bytebuddy;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/**
 * Bootstrap-injected advice: must only use JDK APIs (System.err) — no cross-class calls.
 */
public final class ElytronTraceAdvice {

    private static final String P = "[elytron-trace] ";

    private ElytronTraceAdvice() {
    }

    public static final class Authenticate {
        @Advice.OnMethodEnter
        static void enter(@Advice.Origin("#t.#m") String where) {
            System.err.println(P + ">> " + where);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object returned,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where + " => " + returned);
            }
        }
    }

    public static final class AuthenticationComplete {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
            System.err.println(P + "[KC-GAP] PL=request.authenticationComplete | KC=HttpServerRequest.authenticationComplete(consumer,logoutHandler)");
        }

        @Advice.OnMethodExit
        static void exit(@Advice.Origin("#t.#m") String where) {
            System.err.println(P + "<< " + where);
        }
    }

    public static final class NoAuthenticationInProgress {
        @Advice.OnMethodEnter
        static void enter(@Advice.Origin("#t.#m") String where) {
            System.err.println(P + ">> " + where + " (clears in-progress auth)");
        }
    }

    public static final class AuthenticationInProgress {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }
    }

    public static final class GetRoles {
        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.This(optional = true) Object self,
                @Advice.Return Object roles) {
            System.err.println(P + "!! " + where + " self=" + self + " roles=" + roles);
            if (roles != null && roles.toString().contains("NONE") || (roles != null && roles.toString().equals("[]"))) {
                System.err.println(P + "[KC-GAP] PL=empty roles | KC=SecurityIdentity.getRoles() from realm AuthorizationIdentity");
            }
        }
    }

    public static final class Register {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(2) Object account) {
            System.err.println(P + ">> " + where + " account=" + account);
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object account) {
            System.err.println(P + "<< " + where + " account=" + account);
        }
    }

    public static final class IdentityCompletion {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object result) {
            System.err.println(P + "<< " + where + " => " + result);
        }
    }

    public static final class HttpMechanismEvaluate {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(0) Object request) {
            System.err.println(P + ">> " + where + " request=" + request);
            if (where.contains("PicketLinkSaml")) {
                System.err.println(P + "[KC-GAP] PL=PicketLinkSamlHttpServerAuthenticationMechanism.evaluateRequest | KC=KeycloakHttpServerAuthenticationMechanism.evaluateRequest");
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where);
            }
        }
    }

    public static final class AuthorizationPermit {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object result) {
            System.err.println(P + "<< " + where + " => " + result);
        }
    }

    public static final class RestoreIdentity {
        @Advice.OnMethodEnter
        static void enter(@Advice.Origin("#t.#m") String where) {
            System.err.println(P + ">> " + where);
            System.err.println(P + "[KC-GAP] PL=HttpAuthenticator.restoreIdentity | KC=CachedIdentity from session HttpScope");
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object cachedIdentity) {
            System.err.println(P + "<< " + where + " cachedIdentity=" + cachedIdentity);
        }
    }

    public static final class CachedIdentityCtor {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }
    }

    public static final class CachedIdentityAccess {
        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.This Object self,
                @Advice.Return Object result) {
            System.err.println(P + "!! " + where + " cachedIdentity=" + self + " => " + result);
        }
    }

    public static final class IdentityCacheAccess {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object result) {
            System.err.println(P + "<< " + where + " => " + result);
        }
    }

    public static final class SetIdentity {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(0) Object identity) {
            System.err.println(P + ">> " + where + " identity=" + identity);
        }
    }

    public static final class ServerAuthContext {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
            if (where.contains("authorize")) {
                System.err.println(P + "[KC-GAP] PL=ServerAuthenticationContext.authorize | KC=SecurityIdentityUtil.authorize(callbackHandler, SamlPrincipal)");
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object result,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where + " => " + result);
            }
        }
    }

    public static final class HttpScopeSetAttachment {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(0) Object key,
                @Advice.Argument(1) Object value) {
            System.err.println(P + ">> " + where + " key=" + key + " value=" + value);
            if (key != null && key.toString().contains("CachedIdentity")) {
                System.err.println(P + "[KC-GAP] PL=HttpScope CachedIdentity | KC=HttpAuthenticator session cache");
            }
        }
    }

    public static final class HttpScopeGetAttachment {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(0) Object key) {
            System.err.println(P + ">> " + where + " key=" + key);
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Argument(0) Object key,
                @Advice.Return Object value) {
            System.err.println(P + "<< " + where + " key=" + key + " => " + value);
        }
    }

    public static final class BridgeDelegate {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
            if (where.contains("completeDelegatedAuthentication")) {
                System.err.println(P + "[KC-GAP] PL=completeDelegatedAuthentication | KC=ElytronHttpFacade.authenticationComplete + SecurityIdentityUtil.authorize");
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object returned,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where + " => " + returned);
            }
        }
    }

    public static final class SecurityIdentityUtilAuthorize {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
            System.err.println(P + "[KC-GAP] PL=authorize via callback | KC=SecurityIdentityUtil.authorize(callbackHandler, principal)");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object identity,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where + " SecurityIdentity=" + identity);
            }
        }
    }

    public static final class SessionIdentitySupport {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where);
            }
        }
    }

    public static final class SessionIdentitySupportWithReturn {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
        }

        @Advice.OnMethodExit
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object result) {
            System.err.println(P + "<< " + where + " => " + result);
        }
    }

    public static final class SpMechanismAuthenticate {
        @Advice.OnMethodEnter
        static void enter(
                @Advice.Origin("#t.#m") String where,
                @Advice.AllArguments Object[] args) {
            System.err.println(P + ">> " + where + " args=" + (args == null ? 0 : args.length));
            System.err.println(P + "[KC-GAP] PL=SPFormAuthenticationMechanism (Undertow bridge) | KC=ElytronSamlAuthenticator (all in Elytron layer)");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        static void exit(
                @Advice.Origin("#t.#m") String where,
                @Advice.Return Object authOutcome,
                @Advice.Thrown Throwable thrown) {
            if (thrown != null) {
                System.err.println(P + "<< " + where + " THROW " + thrown);
            } else {
                System.err.println(P + "<< " + where + " AuthOutcome=" + authOutcome);
            }
        }
    }
}
