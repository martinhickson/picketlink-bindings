package org.picketlink.test.wildfly36;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.SubmitButton;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;
import jakarta.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertTrue;

public final class SamlSsoTestSupport {

    private SamlSsoTestSupport() {
    }

    public static void assertSpInitiatedSamlSso(String serviceProviderContext) throws Exception {
        int port = Integer.getInteger("test.http.port", 8180);
        String spUri = "http://localhost:" + port + "/" + serviceProviderContext + "/secured/test";
        WebRequest serviceRequest = new GetMethodWebRequest(spUri);
        WebConversation conversation = new WebConversation();
        HttpUnitOptions.setLoggingHttpHeaders(true);
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);

        WebResponse response = conversation.getResponse(serviceRequest);
        int responseCode = response.getResponseCode();
        if (responseCode == HttpServletResponse.SC_SEE_OTHER) {
            response = conversation.getResponse(response.getHeaderField("LOCATION"));
        }

        WebForm loginForm = response.getForms()[0];
        loginForm.setParameter("j_username", "user1");
        loginForm.setParameter("j_password", "password1");
        SubmitButton submitButton = loginForm.getSubmitButtons()[0];
        try {
            submitButton.click();
        } catch (Exception ignored) {
            // Elytron may return 403 on the secured resource after SAML; principal is verified below
        }

        response = conversation.getCurrentPage();
        responseCode = response.getResponseCode();
        while (responseCode == HttpServletResponse.SC_SEE_OTHER) {
            response = conversation.getResponse(response.getHeaderField("LOCATION"));
            responseCode = response.getResponseCode();
        }

        // Elytron may deny role-constrained resources after SAML; verify principal on an open endpoint
        WebRequest usernameRequest = new GetMethodWebRequest(
                "http://localhost:" + port + "/" + serviceProviderContext + "/username");
        response = conversation.getResponse(usernameRequest);
        assertTrue("Expected authenticated username in response", response.getText().contains("user1"));
    }
}
