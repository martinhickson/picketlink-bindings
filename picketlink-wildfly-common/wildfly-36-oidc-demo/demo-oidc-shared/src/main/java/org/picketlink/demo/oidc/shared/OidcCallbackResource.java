package org.picketlink.demo.oidc.shared;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.net.URI;

@Path("/callback")
public class OidcCallbackResource {

    @GET
    public Response complete() {
        return Response.seeOther(URI.create("../app/secured")).build();
    }
}
