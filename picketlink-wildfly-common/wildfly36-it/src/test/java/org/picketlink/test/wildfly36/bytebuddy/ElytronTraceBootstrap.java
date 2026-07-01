package org.picketlink.test.wildfly36.bytebuddy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Builds a helper jar for ByteBuddy bootstrap injection on WildFly module class loaders.
 */
final class ElytronTraceBootstrap {

    private static final String[] HELPER_CLASSES = {
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$Authenticate.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$AuthenticationComplete.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$NoAuthenticationInProgress.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$AuthenticationInProgress.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$GetRoles.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$Register.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$IdentityCompletion.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$HttpMechanismEvaluate.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$AuthorizationPermit.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$RestoreIdentity.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$CachedIdentityCtor.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$CachedIdentityAccess.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$IdentityCacheAccess.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$SetIdentity.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$ServerAuthContext.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$HttpScopeSetAttachment.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$HttpScopeGetAttachment.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$BridgeDelegate.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$SecurityIdentityUtilAuthorize.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$SessionIdentitySupport.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$SessionIdentitySupportWithReturn.class",
            "org/picketlink/test/wildfly36/bytebuddy/ElytronTraceAdvice$SpMechanismAuthenticate.class",
    };

    private ElytronTraceBootstrap() {
    }

    static Path createHelperJar() throws IOException {
        Path jar = Files.createTempFile("elytron-trace-helper", ".jar");
        jar.toFile().deleteOnExit();
        ClassLoader loader = ElytronTraceBootstrap.class.getClassLoader();
        try (OutputStream out = Files.newOutputStream(jar);
                JarOutputStream jos = new JarOutputStream(out)) {
            for (String entry : HELPER_CLASSES) {
                try (InputStream in = loader.getResourceAsStream(entry)) {
                    if (in == null) {
                        throw new IOException("Missing helper class resource: " + entry);
                    }
                    jos.putNextEntry(new JarEntry(entry));
                    in.transferTo(jos);
                    jos.closeEntry();
                }
            }
        }
        return jar;
    }
}
