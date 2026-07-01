package org.picketlink.test.wildfly36.deployment;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.config.federation.IDPType;
import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.web.config.AbstractSAMLConfigurationProvider;

/**
 * Reads {@code picketlink.xml} from the path in {@code picketlink.test.reload.config.path} on every lookup
 * so timer-based reload picks up external file changes.
 */
public class FileReloadableSAMLConfigurationProvider extends AbstractSAMLConfigurationProvider {

    public static final String CONFIG_PATH_PROPERTY = "picketlink.test.reload.config.path";

    private static final String DEFAULT_CONFIG_FILE_NAME = "picketlink-reload-test.xml";

    private File resolveConfigFile() {
        String path = System.getProperty(CONFIG_PATH_PROPERTY);
        if (path != null && !path.isBlank()) {
            return new File(path);
        }

        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir != null && !configDir.isBlank()) {
            return new File(configDir, DEFAULT_CONFIG_FILE_NAME);
        }

        throw new IllegalStateException("Cannot resolve reloadable PicketLink config file location");
    }

    private void reloadFromFile() throws ProcessingException {
        File configFile = resolveConfigFile();
        if (!configFile.isFile()) {
            throw new IllegalStateException("Reloadable config file not found: " + configFile.getAbsolutePath());
        }

        try (InputStream inputStream = new FileInputStream(configFile)) {
            setConsolidatedConfigFile(inputStream);
        } catch (ParsingException e) {
            throw new ProcessingException(e);
        } catch (IOException e) {
            throw new ProcessingException(e);
        }
    }

    @Override
    public PicketLinkType getPicketLinkConfiguration() throws ProcessingException {
        reloadFromFile();
        return super.getPicketLinkConfiguration();
    }

    @Override
    public SPType getSPConfiguration() throws ProcessingException {
        reloadFromFile();
        return configParsedSPType;
    }

    @Override
    public IDPType getIDPConfiguration() throws ProcessingException {
        reloadFromFile();
        return configParsedIDPType;
    }
}
