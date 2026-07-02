package org.picketlink.test.wildfly36idm.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Stages the unified {@code org.picketlink} WildFly module before integration tests run.
 */
public final class PicketLinkModuleInstaller {

    public static final String MODULE_NAME = "org.picketlink";

    private static final String[] EXCLUDED_JAR_PREFIXES = {
            "jboss-logging-",
            "jakarta.servlet-api-",
            "jakarta.enterprise-",
            "jakarta.inject-",
            "jakarta.persistence-",
            "jakarta.transaction-",
            "jakarta.annotation-",
            "jakarta.el-",
            "jakarta.interceptor-",
            "xml-apis-",
            "javax.activation-",
            "javax.annotation-api-",
            "javax.xml.soap-api-",
            "jaxws-api-",
            "geronimo-jta_1.1_spec-",
            "geronimo-ws-metadata_2.0_spec-",
            "jboss-modules-",
            "jboss-rmi-api_1.0_spec-",
            "xmlsec-"
    };

    private PicketLinkModuleInstaller() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: PicketLinkModuleInstaller <jboss.home> <libs-directory>");
        }
        install(Paths.get(args[0]), Paths.get(args[1]));
    }

    public static void install(Path jbossHome, Path libsDirectory) throws IOException {
        Path moduleDir = jbossHome.resolve("modules").resolve("org").resolve("picketlink").resolve("main");
        if (Files.isDirectory(moduleDir)) {
            try (Stream<Path> existing = Files.list(moduleDir)) {
                existing.forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException e) {
                        throw new IllegalStateException("Failed to clean " + path, e);
                    }
                });
            }
        }
        Files.createDirectories(moduleDir);

        if (!Files.isDirectory(libsDirectory)) {
            throw new IllegalStateException("PicketLink libs directory not found: " + libsDirectory);
        }

        List<String> jarNames = new ArrayList<>();
        try (Stream<Path> jars = Files.list(libsDirectory)) {
            jars.filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(PicketLinkModuleInstaller::includeJar)
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .forEach(jar -> {
                        String jarName = jar.getFileName().toString();
                        jarNames.add(jarName);
                        copyJar(jar, moduleDir.resolve(jarName));
                    });
        }

        if (jarNames.stream().noneMatch(name -> name.startsWith("picketlink-idm-impl"))) {
            throw new IllegalStateException("picketlink-idm-impl jar missing from " + libsDirectory);
        }

        Files.writeString(moduleDir.resolve("module.xml"), buildModuleXml(jarNames), StandardCharsets.UTF_8);
    }

    private static String buildModuleXml(List<String> jarNames) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<module xmlns=\"urn:jboss:module:1.9\" name=\"org.picketlink\">\n");
        xml.append("    <resources>\n");
        for (String jarName : jarNames) {
            xml.append("        <resource-root path=\"").append(jarName).append("\"/>\n");
        }
        xml.append("    </resources>\n");
        xml.append("    <dependencies>\n");
        xml.append("        <module name=\"java.base\"/>\n");
        xml.append("        <module name=\"java.desktop\"/>\n");
        xml.append("        <module name=\"java.logging\"/>\n");
        xml.append("        <module name=\"java.naming\"/>\n");
        xml.append("        <module name=\"java.sql\"/>\n");
        xml.append("        <module name=\"java.xml\"/>\n");
        xml.append("        <module name=\"jakarta.persistence.api\"/>\n");
        xml.append("        <module name=\"jakarta.transaction.api\"/>\n");
        xml.append("        <module name=\"jakarta.enterprise.api\"/>\n");
        xml.append("        <module name=\"org.hibernate\"/>\n");
        xml.append("        <module name=\"org.jboss.logging\"/>\n");
        xml.append("    </dependencies>\n");
        xml.append("</module>\n");
        return xml.toString();
    }

    private static boolean includeJar(Path jar) {
        String name = jar.getFileName().toString();
        if (!name.startsWith("picketlink-")) {
            return false;
        }
        for (String prefix : EXCLUDED_JAR_PREFIXES) {
            if (name.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    private static void copyJar(Path source, Path target) {
        try {
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to copy " + source + " to " + target, e);
        }
    }
}
