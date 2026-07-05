package org.picketlink.demo.oidc.shared;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Clears the RP OIDC token context. {@code GLO=true} also ends the AS browser session.
 */
public class DemoOidcRpLogoutServlet extends HttpServlet {

    public static final String TOKEN_CONTEXT_MANAGER = "picketlink.oidc.rp.tokenContextManager";
    public static final String AS_END_SESSION_URL = "picketlink.oidc.as.endSessionUrl";
    public static final String POST_LOGOUT_REDIRECT_URI = "picketlink.oidc.rp.postLogoutRedirectUri";
    public static final String ID_TOKEN_HINT_SESSION_ATTR = "picketlink.oidc.idTokenHint";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        logout(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        logout(req, resp);
    }

    private void logout(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        boolean global = isTruthy(req.getParameter("GLO"));
        String idTokenHint = clearOidcSession(req);

        if (global) {
            String endSessionUrl = (String) req.getServletContext().getAttribute(AS_END_SESSION_URL);
            String postLogoutRedirect = (String) req.getServletContext().getAttribute(POST_LOGOUT_REDIRECT_URI);
            if (endSessionUrl != null && !endSessionUrl.isBlank()) {
                StringBuilder target = new StringBuilder(endSessionUrl);
                target.append(endSessionUrl.contains("?") ? '&' : '?');
                if (idTokenHint != null && !idTokenHint.isBlank()) {
                    target.append("id_token_hint=")
                            .append(URLEncoder.encode(idTokenHint, StandardCharsets.UTF_8))
                            .append('&');
                }
                if (postLogoutRedirect != null && !postLogoutRedirect.isBlank()) {
                    target.append("post_logout_redirect_uri=")
                            .append(URLEncoder.encode(postLogoutRedirect, StandardCharsets.UTF_8));
                }
                resp.sendRedirect(target.toString());
                return;
            }
        }

        resp.sendRedirect(req.getContextPath() + "/logout.html");
    }

    private static String clearOidcSession(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session == null) {
            return null;
        }
        String idTokenHint = (String) session.getAttribute(ID_TOKEN_HINT_SESSION_ATTR);
        session.removeAttribute(ID_TOKEN_HINT_SESSION_ATTR);
        session.removeAttribute("state");
        session.removeAttribute("org.apache.cxf.websso.context");
        session.removeAttribute("session_authenticity_token");
        session.invalidate();
        return idTokenHint;
    }

    private static boolean isTruthy(String value) {
        return value != null && ("true".equalsIgnoreCase(value) || "1".equals(value) || value.isEmpty());
    }
}
