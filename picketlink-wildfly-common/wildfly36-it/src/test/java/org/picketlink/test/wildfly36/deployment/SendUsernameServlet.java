package org.picketlink.test.wildfly36.deployment;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Principal;

public class SendUsernameServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        writeUsername(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        writeUsername(req, resp);
    }

    private void writeUsername(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        OutputStream stream = resp.getOutputStream();
        Principal principal = req.getUserPrincipal();
        if (principal != null) {
            stream.write(principal.getName().getBytes());
        }
    }
}
