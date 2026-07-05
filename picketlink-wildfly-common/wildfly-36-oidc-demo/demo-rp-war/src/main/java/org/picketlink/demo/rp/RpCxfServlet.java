package org.picketlink.demo.rp;

import jakarta.servlet.ServletConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.picketlink.demo.oidc.shared.DemoInfoResource;
import org.picketlink.demo.oidc.shared.DemoOidcMeResource;
import org.picketlink.demo.oidc.shared.DemoOidcRpLogoutServlet;
import org.picketlink.demo.oidc.shared.OidcCallbackResource;
import org.picketlink.oidc.OidcPathScopedClientCodeRequestFilter;
import org.picketlink.oidc.OidcRelyingPartyBootstrap;

public class RpCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String baseUrl = servletConfig.getServletContext().getInitParameter("demo.base.url");
        String asBaseUrl = servletConfig.getServletContext().getInitParameter("demo.as.base.url");
        String callbackUri = baseUrl + "oidc/callback";
        String logoutPage = baseUrl + "logout.html";

        OidcRelyingPartyBootstrap.RelyingPartySetup setup = OidcRelyingPartyBootstrap.createSetup(
                asBaseUrl + "oidc/authorize",
                asBaseUrl + "oidc/token",
                callbackUri,
                null,
                "me",
                trimTrailingSlash(asBaseUrl),
                asBaseUrl + "oidc/jwks");
        OidcPathScopedClientCodeRequestFilter authFilter = setup.authFilter();

        servletConfig.getServletContext().setAttribute(
                DemoOidcRpLogoutServlet.TOKEN_CONTEXT_MANAGER, setup.tokenContextManager());
        servletConfig.getServletContext().setAttribute(
                DemoOidcRpLogoutServlet.AS_END_SESSION_URL, trimTrailingSlash(asBaseUrl) + "/idp/logout");
        servletConfig.getServletContext().setAttribute(
                DemoOidcRpLogoutServlet.POST_LOGOUT_REDIRECT_URI, logoutPage);

        Map<String, String> links = new LinkedHashMap<>();
        links.put("home", baseUrl + "app/");
        links.put("securedApp", baseUrl + "app/secured");
        links.put("admin", baseUrl + "app/admin");
        links.put("oidcCallback", callbackUri);
        links.put("asDiscovery", asBaseUrl + ".well-known/openid-configuration");
        links.put("asJwks", asBaseUrl + "oidc/jwks");
        links.put("asHome", asBaseUrl + "app/");

        ArrayList<Object> providers = new ArrayList<>();
        providers.addAll(Arrays.asList(OidcRelyingPartyBootstrap.defaultProviders(authFilter)));

        JAXRSServerFactoryBean apiServer = new JAXRSServerFactoryBean();
        apiServer.setBus(getBus());
        apiServer.setProviders(providers);
        apiServer.setServiceBeans(Arrays.asList(
                new DemoInfoResource("OIDC-RP", baseUrl, links),
                new DemoOidcMeResource(),
                new OidcCallbackResource()));
        apiServer.setAddress("/");
        apiServer.create();
    }

    private static String trimTrailingSlash(String url) {
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }
}
