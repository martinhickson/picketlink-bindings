package org.picketlink.demo.shared;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;

@Path("/info")
public class DemoInfoResource {

    private final String role;
    private final String baseUrl;
    private final Map<String, String> links;

    public DemoInfoResource(String role, String baseUrl, Map<String, String> links) {
        this.role = role;
        this.baseUrl = baseUrl;
        this.links = links;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String info() {
        StringBuilder json = new StringBuilder();
        json.append("{\"role\":\"").append(escape(role)).append("\",");
        json.append("\"baseUrl\":\"").append(escape(baseUrl)).append("\",");
        json.append("\"api\":\"").append(escape(baseUrl + "api/info")).append("\",");
        json.append("\"links\":{");
        boolean first = true;
        for (Map.Entry<String, String> link : links.entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('"').append(escape(link.getKey())).append("\":\"")
                    .append(escape(link.getValue())).append('"');
        }
        json.append("}}");
        return json.toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
