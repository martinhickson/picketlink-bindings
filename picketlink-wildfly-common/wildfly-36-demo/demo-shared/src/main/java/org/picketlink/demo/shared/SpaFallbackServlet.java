package org.picketlink.demo.shared;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * Serves the Angular build under {@code /app/*}, with {@code index.html} fallback for client routes.
 */
public class SpaFallbackServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();
        if (path == null || path.isEmpty() || "/".equals(path)) {
            serveIndex(resp);
            return;
        }
        if (path.contains(".")) {
            serveStatic(resp, "/app" + path);
            return;
        }
        serveIndex(resp);
    }

    private void serveIndex(HttpServletResponse resp) throws IOException {
        serveStatic(resp, "/app/index.html");
    }

    private void serveStatic(HttpServletResponse resp, String resourcePath) throws IOException {
        try (InputStream resource = getServletContext().getResourceAsStream(resourcePath)) {
            if (resource == null) {
                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Missing " + resourcePath);
                return;
            }
            if (resourcePath.endsWith(".html")) {
                resp.setContentType("text/html;charset=UTF-8");
            } else if (resourcePath.endsWith(".js")) {
                resp.setContentType("application/javascript;charset=UTF-8");
            } else if (resourcePath.endsWith(".css")) {
                resp.setContentType("text/css;charset=UTF-8");
            }
            resource.transferTo(resp.getOutputStream());
        }
    }
}
