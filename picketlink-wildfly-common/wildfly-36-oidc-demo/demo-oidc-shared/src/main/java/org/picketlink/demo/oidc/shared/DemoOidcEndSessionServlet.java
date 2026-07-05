package org.picketlink.demo.oidc.shared;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

/** OIDC RP-initiated logout endpoint ({@code end_session_endpoint}). */
public class DemoOidcEndSessionServlet extends HttpServlet {

    public static final String ALLOWED_POST_LOGOUT_REDIRECT_URI = "picketlink.oidc.as.allowedPostLogoutRedirectUri";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        endSession(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        endSession(req, resp);
    }

    private void endSession(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        try {
            req.logout();
        } catch (ServletException ignored) {
        }
        HttpSession session = req.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        String redirect = req.getParameter("post_logout_redirect_uri");
        String allowed = (String) req.getServletContext().getAttribute(ALLOWED_POST_LOGOUT_REDIRECT_URI);
        if (redirect != null && allowed != null && allowed.equals(redirect)) {
            resp.sendRedirect(redirect);
            return;
        }
        resp.sendRedirect(req.getContextPath() + "/app/");
    }
}
