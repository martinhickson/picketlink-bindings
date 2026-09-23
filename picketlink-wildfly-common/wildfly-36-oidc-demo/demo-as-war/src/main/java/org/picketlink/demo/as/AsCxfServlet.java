package org.picketlink.demo.as;

import jakarta.servlet.ServletConfig;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.picketlink.demo.oidc.shared.DemoInfoResource;
import org.picketlink.demo.oidc.shared.DemoOidcEndSessionServlet;
import org.picketlink.oidc.OidcAuthorizationServerBootstrap;
import org.picketlink.oidc.OidcAuthorizationServerConfig;
import org.picketlink.oidc.OidcClientRegistration;
import org.picketlink.oidc.OidcDemoConstants;
import org.picketlink.oidc.OidcKeystoreConfig;
import org.picketlink.oidc.OidcUserRegistration;

public class AsCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String baseUrl = servletConfig.getServletContext().getInitParameter("demo.base.url");
        String rpRedirectUri = servletConfig.getServletContext().getInitParameter("demo.rp.redirect.uri");
        String rpBaseUrl = servletConfig.getServletContext().getInitParameter("demo.rp.base.url");
        servletConfig.getServletContext().setAttribute(
                DemoOidcEndSessionServlet.ALLOWED_POST_LOGOUT_REDIRECT_URI, rpBaseUrl + "logout.html");

        Map<String, String> links = new LinkedHashMap<>();
        links.put("home", baseUrl + "app/");
        links.put("admin", baseUrl + "app/admin");
        links.put("login", baseUrl + "FormLoginServlet");
        links.put("oidcDiscovery", baseUrl + ".well-known/openid-configuration");
        links.put("authorize", baseUrl + "oidc/authorize");
        links.put("token", baseUrl + "oidc/token");
        links.put("jwks", baseUrl + "oidc/jwks");
        links.put("rpHome", servletConfig.getServletContext().getInitParameter("demo.rp.base.url") + "app/");

        OidcKeystoreConfig keystore = null;
        String keystorePath = System.getProperty("picketlink.test.keystore.path");
        if (keystorePath != null && !keystorePath.isBlank()) {
            keystore = new OidcKeystoreConfig(
                    Path.of(keystorePath),
                    OidcDemoConstants.KEYSTORE_PASSWORD,
                    OidcDemoConstants.KEYSTORE_KEY_PASSWORD,
                    OidcDemoConstants.KEYSTORE_ALIAS,
                    OidcDemoConstants.KEYSTORE_TYPE);
        }
        OidcAuthorizationServerConfig config = OidcAuthorizationServerConfig.builder(baseUrl)
                .client(OidcClientRegistration.builder(
                        OidcDemoConstants.CLIENT_ID, OidcDemoConstants.CLIENT_SECRET)
                        .redirectUri(rpRedirectUri)
                        .scope(OidcDemoConstants.OPENID_SCOPE)
                        .scope(OidcDemoConstants.PROFILE_SCOPE)
                        .grantType("authorization_code")
                        .grantType("refresh_token")
                        .applicationName("PicketLink Demo RP")
                        .build())
                .user(new OidcUserRegistration(
                        OidcDemoConstants.DEMO_USERNAME,
                        OidcDemoConstants.DEMO_PASSWORD,
                        List.of(OidcDemoConstants.DEMO_ROLE)))
                .keystore(keystore)
                .build();
        OidcAuthorizationServerBootstrap.mount(getBus(), config, Arrays.asList(
                new DemoInfoResource("OIDC-AS", baseUrl, links)));
    }
}
