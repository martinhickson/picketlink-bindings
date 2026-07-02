package org.picketlink.demo.shared;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.security.Principal;

/**
 * Secured session probe for SPA route guards ({@code GET /api/me}).
 */
@Path("/me")
public class DemoMeResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response me(@Context HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        if (principal == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"authenticated\":false}")
                    .build();
        }
        StringBuilder json = new StringBuilder();
        json.append("{\"authenticated\":true,\"username\":\"")
                .append(escape(principal.getName()))
                .append("\",\"roles\":[");
        if (request.isUserInRole("role1")) {
            json.append("\"role1\"");
        }
        json.append("]}");
        return Response.ok(json.toString()).build();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
