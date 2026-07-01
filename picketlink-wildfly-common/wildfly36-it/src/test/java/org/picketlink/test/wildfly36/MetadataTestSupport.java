package org.picketlink.test.wildfly36;

import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public final class MetadataTestSupport {

    private MetadataTestSupport() {
    }

    public static void assertIdpMetadataEndpoint() throws Exception {
        assertIdpMetadataEndpoint("idp-metadata", false);
    }

    public static void assertIdpGeneratedMetadataEndpoint() throws Exception {
        assertIdpMetadataEndpoint("idp-metadata-generated", true);
    }

    private static void assertIdpMetadataEndpoint(String context, boolean generated) throws Exception {
        HttpResponse<String> response = fetchMetadata(context);
        assertEquals(HttpServletResponse.SC_OK, response.statusCode());
        assertTrue("Expected SAML metadata content type",
                response.headers().firstValue("content-type").orElse("").contains("application/samlmetadata+xml"));

        String body = response.body();
        String base = "http://localhost:" + port() + "/" + context + "/";
        assertTrue("Expected EntityDescriptor", body.contains("EntityDescriptor"));
        assertTrue("Expected IDPSSODescriptor", body.contains("IDPSSODescriptor"));
        assertTrue("Expected IDP entity ID", body.contains(base));
        assertTrue("Expected SingleSignOnService", body.contains("SingleSignOnService"));
        assertTrue("Expected SingleLogoutService", body.contains("SingleLogoutService"));
        assertTrue("Expected signing KeyDescriptor from keystore", body.contains("KeyDescriptor"));
        assertTrue("Expected X509Certificate in metadata", body.contains("X509Certificate"));
        if (generated) {
            assertTrue("Expected signed metadata", body.contains("Signature"));
            assertTrue("Expected IDP logout response location from HostedURI",
                    body.contains(base + "logout-done"));
        }
    }

    public static void assertSpMetadataEndpoint() throws Exception {
        assertSpMetadataEndpoint("sp-metadata", false);
    }

    public static void assertSpGeneratedMetadataEndpoint() throws Exception {
        assertSpMetadataEndpoint("sp-metadata-generated", true);
    }

    private static void assertSpMetadataEndpoint(String context, boolean generated) throws Exception {
        HttpResponse<String> response = fetchMetadata(context);
        assertEquals(HttpServletResponse.SC_OK, response.statusCode());
        assertTrue("Expected SAML metadata content type",
                response.headers().firstValue("content-type").orElse("").contains("application/samlmetadata+xml"));

        String body = response.body();
        String base = "http://localhost:" + port() + "/" + context + "/";
        assertTrue("Expected EntityDescriptor", body.contains("EntityDescriptor"));
        assertTrue("Expected SPSSODescriptor", body.contains("SPSSODescriptor"));
        assertTrue("Expected SP entity ID", body.contains(base));
        assertTrue("Expected AssertionConsumerService", body.contains("AssertionConsumerService"));
        assertTrue("Expected SP service URL", body.contains(base));
        assertTrue("Expected signing KeyDescriptor from keystore", body.contains("KeyDescriptor"));
        assertTrue("Expected X509Certificate in metadata", body.contains("X509Certificate"));
        if (generated) {
            assertTrue("Expected SingleLogoutService", body.contains("SingleLogoutService"));
            assertTrue("Expected signed metadata", body.contains("Signature"));
            assertTrue("Expected SLO Location at service URL",
                    body.contains("SingleLogoutService") && body.contains(base));
            assertTrue("Expected SLO ResponseLocation from LogOutPage",
                    body.contains(base + "logout.html"));
        }
    }

    private static HttpResponse<String> fetchMetadata(String context) throws Exception {
        String uri = "http://localhost:" + port() + "/" + context + "/metadata";
        return HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder().uri(URI.create(uri)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    public static void assertAdminJsonMetadataDisabled(String context) throws Exception {
        HttpResponse<String> response = fetchAdminJsonMetadata(context);
        assertEquals("Admin JSON metadata should be disabled by default", HttpServletResponse.SC_NOT_FOUND,
                response.statusCode());
    }

    public static void assertAdminJsonMetadataRequiresAuthentication(String context) throws Exception {
        HttpResponse<String> response = fetchAdminJsonMetadata(context);
        assertEquals("Admin JSON metadata should require authentication by default",
                HttpServletResponse.SC_UNAUTHORIZED, response.statusCode());
    }

    /**
     * Verifies PicketLink defaults when {@code MetadataPublishing} is absent or has no attributes:
     * {@code XmlEnabled=true}, {@code AdminJsonEnabled=false}.
     */
    public static void assertMetadataPublishingAttributeDefaults(String context) throws Exception {
        HttpResponse<String> xmlResponse = fetchMetadata(context);
        assertEquals("XmlEnabled should default to true", HttpServletResponse.SC_OK, xmlResponse.statusCode());
        assertTrue("Expected SAML metadata content type",
                xmlResponse.headers().firstValue("content-type").orElse("").contains("application/samlmetadata+xml"));

        assertAdminJsonMetadataDisabled(context);
    }

    public static void assertAdminJsonMetadataEnabled(String context) throws Exception {
        HttpResponse<String> response = fetchAdminJsonMetadata(context);
        assertEquals(HttpServletResponse.SC_OK, response.statusCode());
        assertTrue("Expected JSON content type",
                response.headers().firstValue("content-type").orElse("").contains("application/json"));
        String body = response.body();
        assertTrue("Expected entityId in JSON", body.contains("\"entityId\""));
        assertTrue("Expected SP role in JSON", body.contains("\"role\""));
        assertTrue("Expected assertionConsumerServices in JSON", body.contains("assertionConsumerServices"));
    }

    private static HttpResponse<String> fetchAdminJsonMetadata(String context) throws Exception {
        String uri = "http://localhost:" + port() + "/" + context + "/api/admin/federation/metadata";
        return HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder().uri(URI.create(uri)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    private static int port() {
        return Integer.getInteger("test.http.port", 8180);
    }
}
