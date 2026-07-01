package org.picketlink.test.wildfly36.bytebuddy;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

/**
 * Installs ByteBuddy and Elytron trace agent as WildFly modules and patches Elytron modules
 * so advice classes are visible across JBoss Modules class loaders.
 */
public final class TraceModuleInstaller {

    private static final String TRACE_MODULE = "org.picketlink.elytron-trace";
    private static final String TRACE_DEPENDENCY =
            "        <module name=\"" + TRACE_MODULE + "\" optional=\"true\"/>";

    private static final List<String> PATCH_TARGETS = List.of(
            "system/layers/base/org/wildfly/security/elytron-web/undertow-server/main/module.xml",
            "system/layers/base/org/wildfly/security/elytron-web/undertow-server-servlet/main/module.xml",
            "system/layers/base/org/wildfly/security/elytron-base/main/module.xml",
            "system/layers/base/org/wildfly/security/elytron-private/main/module.xml");

    private TraceModuleInstaller() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: TraceModuleInstaller <jboss.home> <trace-modules-staging>");
        }
        Path jbossHome = Path.of(args[0]);
        Path staging = Path.of(args[1]);
        Path modulesRoot = jbossHome.resolve("modules");

        copyTree(staging, modulesRoot);
        for (String relative : PATCH_TARGETS) {
            patchModule(modulesRoot.resolve(relative));
        }
        System.out.println("[elytron-trace] Installed trace modules under " + modulesRoot);
    }

    private static void copyTree(Path source, Path target) throws IOException {
        if (!Files.isDirectory(source)) {
            throw new IllegalStateException("Trace module staging directory not found: " + source);
        }
        Files.walkFileTree(source, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                Path destination = target.resolve(source.relativize(dir));
                Files.createDirectories(destination);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Path destination = target.resolve(source.relativize(file));
                Files.createDirectories(destination.getParent());
                Files.copy(file, destination, StandardCopyOption.REPLACE_EXISTING);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void patchModule(Path moduleXml) throws IOException {
        if (!Files.isRegularFile(moduleXml)) {
            System.out.println("[elytron-trace] Skip missing module: " + moduleXml);
            return;
        }
        String content = Files.readString(moduleXml);
        if (content.contains(TRACE_MODULE)) {
            System.out.println("[elytron-trace] Already patched: " + moduleXml);
            return;
        }
        int closing = content.lastIndexOf("</dependencies>");
        if (closing < 0) {
            throw new IllegalStateException("No </dependencies> in " + moduleXml);
        }
        String patched = content.substring(0, closing) + TRACE_DEPENDENCY + System.lineSeparator()
                + "    " + content.substring(closing);
        Files.writeString(moduleXml, patched);
        System.out.println("[elytron-trace] Patched: " + moduleXml);
    }
}
