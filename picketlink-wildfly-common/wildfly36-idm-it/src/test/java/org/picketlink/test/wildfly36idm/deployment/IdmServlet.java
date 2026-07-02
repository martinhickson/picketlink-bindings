package org.picketlink.test.wildfly36idm.deployment;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "IdmServlet", urlPatterns = "/idm/*")
public class IdmServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private IdmUserService userService;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String path = request.getPathInfo();
        if (path == null || "/status".equals(path)) {
            response.setContentType("text/plain");
            response.getWriter().write("OK");
            return;
        }

        if (path.startsWith("/user/")) {
            String loginName = path.substring("/user/".length());
            boolean exists = userService.userExists(loginName);
            response.setContentType("text/plain");
            response.setStatus(exists ? HttpServletResponse.SC_OK : HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().write(exists ? loginName : "missing");
            return;
        }

        response.sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String path = request.getPathInfo();
        if (path != null && path.startsWith("/user/")) {
            String loginName = path.substring("/user/".length());
            userService.createUser(loginName);
            response.setContentType("text/plain");
            response.getWriter().write(loginName);
            return;
        }

        response.sendError(HttpServletResponse.SC_NOT_FOUND);
    }
}
