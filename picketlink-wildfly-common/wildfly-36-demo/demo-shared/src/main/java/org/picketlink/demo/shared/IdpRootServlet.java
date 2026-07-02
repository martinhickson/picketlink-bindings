package org.picketlink.demo.shared;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles the IDP context root ({@code /}) where SAML AuthnRequests arrive.
 * PicketLink {@code IDPFilter} processes SAML once the user is authenticated;
 * this servlet satisfies the {@code /*} mapping for any remaining dispatch.
 */
public class IdpRootServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        handle(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        handle(req, resp);
    }

    private void handle(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (req.getUserPrincipal() != null) {
            resp.sendRedirect(req.getContextPath() + "/app/admin");
        } else {
            resp.sendRedirect(req.getContextPath() + "/FormLoginServlet");
        }
    }
}
