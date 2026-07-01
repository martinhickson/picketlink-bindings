package org.picketlink.test.wildfly36;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.SubmitButton;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.picketlink.common.constants.GeneralConstants;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class SamlSsoTestSupport {

    private SamlSsoTestSupport() {
    }

    public static void assertSpInitiatedSamlSso(String serviceProviderContext) throws Exception {
        WebConversation conversation = new WebConversation();
        loginSpInitiatedSso(conversation, serviceProviderContext);
    }

    /**
     * Attempts SP-initiated SSO and asserts the user is not authenticated on the secured resource.
     */
    public static void assertSpInitiatedSamlSsoFails(String serviceProviderContext) throws Exception {
        WebConversation conversation = new WebConversation();
        WebResponse response = attemptSpInitiatedSso(conversation, serviceProviderContext);
        assertFalse("Expected authentication to fail for " + serviceProviderContext,
                response.getText().contains("user1"));
    }

    /**
     * Logs in via SP-initiated SSO, performs global logout ({@code GLO=true}), then verifies
     * the secured resource requires authentication again.
     */
    public static void assertSpGlobalLogout(String serviceProviderContext) throws Exception {
        WebConversation conversation = new WebConversation();
        HttpUnitOptions.setLoggingHttpHeaders(true);

        loginSpInitiatedSso(conversation, serviceProviderContext);

        int port = Integer.getInteger("test.http.port", 8180);
        String logoutUri = "http://localhost:" + port + "/" + serviceProviderContext
                + "/secured/test?" + GeneralConstants.GLOBAL_LOGOUT + "=true";
        WebResponse response = followSamlLogoutFlow(conversation, new GetMethodWebRequest(logoutUri));

        assertTrue("Expected global logout confirmation page",
                response.getText().contains("Logged out"));

        String securedUri = "http://localhost:" + port + "/" + serviceProviderContext + "/secured/test";
        HttpResponse<String> securedCheck = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
                .send(HttpRequest.newBuilder().uri(URI.create(securedUri)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());

        assertFalse("Secured resource should require re-authentication after global logout",
                securedCheck.body().contains("user1"));
        assertTrue("Expected SP to initiate a fresh SAML challenge after logout",
                isFreshSamlChallenge(securedCheck));
    }

    /**
     * Logs in via SP-initiated SSO, performs local logout ({@code LLO=true}), then verifies
     * the secured resource requires authentication again.
     */
    public static void assertSpLocalLogout(String serviceProviderContext) throws Exception {
        WebConversation conversation = new WebConversation();
        HttpUnitOptions.setLoggingHttpHeaders(true);

        loginSpInitiatedSso(conversation, serviceProviderContext);

        int port = Integer.getInteger("test.http.port", 8180);
        String logoutUri = "http://localhost:" + port + "/" + serviceProviderContext
                + "/secured/test?" + GeneralConstants.LOCAL_LOGOUT + "=true";
        WebResponse response = conversation.getResponse(new GetMethodWebRequest(logoutUri));
        if (response.getResponseCode() == HttpServletResponse.SC_FOUND
                || response.getResponseCode() == HttpServletResponse.SC_MOVED_TEMPORARILY
                || response.getResponseCode() == HttpServletResponse.SC_SEE_OTHER) {
            response = conversation.getResponse(response.getHeaderField("LOCATION"));
        }

        assertTrue("Expected local logout confirmation page",
                response.getText().contains("Logged out"));

        String securedUri = "http://localhost:" + port + "/" + serviceProviderContext + "/secured/test";
        HttpResponse<String> securedCheck = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
                .send(HttpRequest.newBuilder().uri(URI.create(securedUri)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());

        assertFalse("Secured resource should require re-authentication after local logout",
                securedCheck.body().contains("user1"));
        assertTrue("Expected SP to initiate a fresh SAML challenge after logout",
                isFreshSamlChallenge(securedCheck));
    }

    private static boolean isFreshSamlChallenge(HttpResponse<String> response) {
        if (response.statusCode() == HttpServletResponse.SC_FOUND) {
            return response.headers().firstValue("location").orElse("").contains("/idp/");
        }
        if (response.statusCode() == HttpServletResponse.SC_OK) {
            String body = response.body();
            return body.contains("SAMLRequest") || body.contains("SAMLResponse");
        }
        return false;
    }

    private static void loginSpInitiatedSso(WebConversation conversation, String serviceProviderContext)
            throws Exception {
        WebResponse response = attemptSpInitiatedSso(conversation, serviceProviderContext);
        assertTrue("Expected authenticated username on secured resource",
                response.getText().contains("user1"));
    }

    private static WebResponse attemptSpInitiatedSso(WebConversation conversation, String serviceProviderContext)
            throws Exception {
        int port = Integer.getInteger("test.http.port", 8180);
        String spUri = "http://localhost:" + port + "/" + serviceProviderContext + "/secured/test";
        WebResponse response = followRedirects(conversation, new GetMethodWebRequest(spUri));

        WebForm loginForm = response.getForms()[0];
        loginForm.setParameter("j_username", "user1");
        loginForm.setParameter("j_password", "password1");
        SubmitButton submitButton = loginForm.getSubmitButtons()[0];
        submitButton.click();

        return followRedirects(conversation, conversation.getCurrentPage());
    }

    private static WebResponse followSamlLogoutFlow(WebConversation conversation, WebRequest request)
            throws Exception {
        WebResponse response = conversation.getResponse(request);
        for (int step = 0; step < 12; step++) {
            int responseCode = response.getResponseCode();
            if (responseCode == HttpServletResponse.SC_SEE_OTHER
                    || responseCode == HttpServletResponse.SC_MOVED_TEMPORARILY
                    || responseCode == HttpServletResponse.SC_FOUND) {
                response = conversation.getResponse(response.getHeaderField("LOCATION"));
                continue;
            }
            if (response.getText().contains("Logged out")) {
                return response;
            }
            WebForm[] forms = response.getForms();
            if (forms.length > 0 && hasSamlParameter(forms[0])) {
                WebForm samlForm = forms[0];
                SubmitButton[] buttons = samlForm.getSubmitButtons();
                if (buttons.length > 0) {
                    buttons[0].click();
                    response = conversation.getCurrentPage();
                } else {
                    response = samlForm.submit();
                }
                continue;
            }
            break;
        }
        return followRedirects(conversation, response);
    }

    private static boolean hasSamlParameter(WebForm form) {
        for (String name : form.getParameterNames()) {
            if ("SAMLRequest".equals(name) || "SAMLResponse".equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static WebResponse followRedirects(WebConversation conversation, WebResponse response)
            throws Exception {
        int responseCode = response.getResponseCode();
        while (responseCode == HttpServletResponse.SC_SEE_OTHER
                || responseCode == HttpServletResponse.SC_MOVED_TEMPORARILY
                || responseCode == HttpServletResponse.SC_FOUND) {
            response = conversation.getResponse(response.getHeaderField("LOCATION"));
            responseCode = response.getResponseCode();
        }
        return response;
    }

    private static WebResponse followRedirects(WebConversation conversation, WebRequest request)
            throws Exception {
        return followRedirects(conversation, conversation.getResponse(request));
    }
}
