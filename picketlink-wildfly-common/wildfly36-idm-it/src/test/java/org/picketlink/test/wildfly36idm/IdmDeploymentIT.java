package org.picketlink.test.wildfly36idm;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.PostMethodWebRequest;
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
import org.picketlink.test.wildfly36idm.deployment.IdmDeployments;
import org.picketlink.test.wildfly36idm.support.IdmTestSetup;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Arquillian.class)
@RunAsClient
@ServerSetup(IdmTestSetup.class)
public class IdmDeploymentIT {

    @Deployment(name = "idm", testable = false)
    public static WebArchive deployIdm() {
        return IdmDeployments.idmWar();
    }

    @Test
    public void testCreateAndLookupUser() throws Exception {
        int port = Integer.getInteger("test.http.port", 8580);
        WebConversation conversation = new WebConversation();

        WebRequest statusRequest = new GetMethodWebRequest("http://localhost:" + port + "/idm/idm/status");
        WebResponse statusResponse = conversation.getResponse(statusRequest);
        assertEquals(HttpServletResponse.SC_OK, statusResponse.getResponseCode());
        assertTrue(statusResponse.getText().contains("OK"));

        String loginName = "idm-it-user";
        WebRequest createRequest = new PostMethodWebRequest("http://localhost:" + port + "/idm/idm/user/" + loginName);
        WebResponse createResponse = conversation.getResponse(createRequest);
        assertEquals(HttpServletResponse.SC_OK, createResponse.getResponseCode());
        assertTrue(createResponse.getText().contains(loginName));

        WebRequest lookupRequest = new GetMethodWebRequest("http://localhost:" + port + "/idm/idm/user/" + loginName);
        WebResponse lookupResponse = conversation.getResponse(lookupRequest);
        assertEquals(HttpServletResponse.SC_OK, lookupResponse.getResponseCode());
        assertTrue(lookupResponse.getText().contains(loginName));
    }
}
