package org.picketlink.demo.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

public final class PicketLinkModuleInstaller {

    public static final String MODULE_NAME = "org.picketlink";

    private static final String[] EXCLUDED_JAR_PREFIXES = {
            "jboss-logging-",
            "jakarta.servlet-api-",
            "xml-apis-",
            "javax.activation-",
            "javax.annotation-api-",
            "javax.xml.soap-api-",
            "jaxws-api-",
            "geronimo-jta_1.1_spec-",
            "geronimo-ws-metadata_2.0_spec-",
            "jboss-modules-",
            "jboss-rmi-api_1.0_spec-",
            "xmlsec-",
            "wildfly-"
    };

    private PicketLinkModuleInstaller() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: PicketLinkModuleInstaller <jboss.home> <libs-directory>");
        }
        install(Path.of(args[0]), Path.of(args[1]));
    }

    public static void install(Path jbossHome, Path libsDirectory) throws IOException {
        Path moduleDir = jbossHome.resolve("modules/org/picketlink/main");
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
                        try {
                            Files.copy(jar, moduleDir.resolve(jarName),
                                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    });
        }

        if (jarNames.stream().noneMatch(name -> name.startsWith("picketlink-wildfly-common"))) {
            throw new IllegalStateException("picketlink-wildfly-common jar missing from " + libsDirectory);
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
        xml.append("        <module name=\"java.logging\"/>\n");
        xml.append("        <module name=\"java.naming\"/>\n");
        xml.append("        <module name=\"java.security.sasl\"/>\n");
        xml.append("        <module name=\"java.xml\"/>\n");
        xml.append("        <module name=\"java.xml.crypto\"/>\n");
        xml.append("        <module name=\"jakarta.xml.bind.api\"/>\n");
        xml.append("        <module name=\"org.apache.santuario.xmlsec\"/>\n");
        xml.append("        <module name=\"org.wildfly.security.elytron\"/>\n");
        xml.append("        <module name=\"org.wildfly.security.elytron-web.undertow-server\"/>\n");
        xml.append("        <module name=\"org.wildfly.security.elytron-web.undertow-server-servlet\"/>\n");
        xml.append("        <module name=\"io.undertow.core\"/>\n");
        xml.append("        <module name=\"io.undertow.servlet\"/>\n");
        xml.append("        <module name=\"jakarta.servlet.api\"/>\n");
        xml.append("        <module name=\"org.jboss.logging\"/>\n");
        xml.append("        <module name=\"org.picketlink.elytron-trace\" optional=\"true\"/>\n");
        xml.append("    </dependencies>\n");
        xml.append("</module>\n");
        return xml.toString();
    }

    private static boolean includeJar(Path jar) {
        String name = jar.getFileName().toString();
        for (String prefix : EXCLUDED_JAR_PREFIXES) {
            if (name.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }
}
