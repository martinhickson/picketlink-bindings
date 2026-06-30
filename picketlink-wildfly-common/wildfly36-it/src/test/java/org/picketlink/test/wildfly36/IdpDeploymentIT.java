package org.picketlink.test.wildfly36;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.picketlink.test.wildfly36.deployment.SamlDeployments;
import org.picketlink.test.wildfly36.support.ElytronTestSetup;

import static org.junit.Assert.assertTrue;

@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup(ElytronTestSetup.class)
public class IdpDeploymentIT {

    @Deployment(name = "idp", testable = false)
    public static WebArchive deployIdp() {
        return SamlDeployments.idpWar();
    }

    @Test
    public void testIdpRequiresAuthentication() throws Exception {
        WebConversation conversation = new WebConversation();
        int port = Integer.getInteger("test.http.port", 8180);
        WebRequest request = new GetMethodWebRequest("http://localhost:" + port + "/idp/secured");
        WebResponse response = conversation.getResponse(request);

        int responseCode = response.getResponseCode();
        if (responseCode == HttpServletResponse.SC_SEE_OTHER) {
            response = conversation.getResponse(response.getHeaderField("LOCATION"));
        }

        assertTrue("IDP should redirect to form login", response.getText().contains("Login Page"));
    }
}
