package org.picketlink.demo.as;

import jakarta.servlet.ServletConfig;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.picketlink.demo.oidc.shared.DemoInfoResource;
import org.picketlink.demo.oidc.shared.DemoOidcEndSessionServlet;
import org.picketlink.oidc.OidcAuthorizationServerBootstrap;
import org.picketlink.oidc.OidcKeystoreSupport;

public class AsCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String baseUrl = servletConfig.getServletContext().getInitParameter("demo.base.url");
        String rpRedirectUri = servletConfig.getServletContext().getInitParameter("demo.rp.redirect.uri");
        String keystorePath = System.getProperty("picketlink.test.keystore.path");
        if (keystorePath != null && !keystorePath.isBlank()) {
            try {
                OidcKeystoreSupport.bootstrap(getBus(), Path.of(keystorePath));
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to bootstrap OIDC signing keystore", ex);
            }
        }

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

        OidcAuthorizationServerBootstrap.mount(getBus(), baseUrl, rpRedirectUri, Arrays.asList(
                new DemoInfoResource("OIDC-AS", baseUrl, links)));
    }
}
