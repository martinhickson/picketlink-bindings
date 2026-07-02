package org.picketlink.demo.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public final class DemoWarSupport {

    private static final Set<String> PICKETLINK_CONFIG_ENTRIES = Set.of(
            "WEB-INF/picketlink.xml",
            "WEB-INF/metadata-config.xml");

    private DemoWarSupport() {
    }

    public static Path withKeystorePath(Path sourceWar, Path keystorePath) throws IOException {
        Path patchedWar = Files.createTempFile("demo-patched-", ".war");
        String keystoreValue = keystorePath.toAbsolutePath().toString().replace('\\', '/');
        try (InputStream in = Files.newInputStream(sourceWar);
             ZipInputStream zipIn = new ZipInputStream(in);
             OutputStream out = Files.newOutputStream(patchedWar);
             ZipOutputStream zipOut = new ZipOutputStream(out)) {
            ZipEntry entry;
            while ((entry = zipIn.getNextEntry()) != null) {
                ZipEntry outEntry = new ZipEntry(entry.getName());
                zipOut.putNextEntry(outEntry);
                if (PICKETLINK_CONFIG_ENTRIES.contains(entry.getName())) {
                    String xml = new String(zipIn.readAllBytes());
                    xml = xml.replace("jbid_test_keystore.jks", keystoreValue);
                    xml = xml.replace("${picketlink.test.keystore.path}", keystoreValue);
                    zipOut.write(xml.getBytes());
                } else {
                    zipIn.transferTo(zipOut);
                }
                zipOut.closeEntry();
                zipIn.closeEntry();
            }
        }
        return patchedWar;
    }
}
