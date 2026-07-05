package org.picketlink.demo.oidc.shared;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.rp.OidcClientTokenContext;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

@Path("/me")
public class DemoOidcMeResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response me(@Context OidcClientTokenContext context, @Context HttpServletRequest request) {
        ClientAccessToken token = context == null ? null : context.getToken();
        if (token == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"authenticated\":false}")
                    .build();
        }
        rememberIdTokenHint(request, token);
        IdToken idToken = context.getIdToken();
        String username = idToken == null ? "unknown" : idToken.getSubject();
        StringBuilder json = new StringBuilder();
        json.append("{\"authenticated\":true,\"username\":\"")
                .append(escape(username))
                .append("\",\"tokenType\":\"")
                .append(escape(token.getTokenType()))
                .append("\",\"roles\":[\"role1\"]}");
        return Response.ok(json.toString()).build();
    }

    private static void rememberIdTokenHint(HttpServletRequest request, ClientAccessToken token) {
        if (request == null || token.getParameters() == null) {
            return;
        }
        String idToken = token.getParameters().get(OidcUtils.ID_TOKEN);
        if (idToken != null && !idToken.isBlank()) {
            request.getSession().setAttribute(DemoOidcRpLogoutServlet.ID_TOKEN_HINT_SESSION_ATTR, idToken);
        }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
