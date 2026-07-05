package org.picketlink.demo.oidc.shared;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import org.picketlink.oidc.OidcDemoConstants;

public class AsFormLoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html;charset=UTF-8");
        Writer writer = resp.getWriter();
        writer.write("<!DOCTYPE html><html><head><title>OIDC Login</title></head><body>");
        writer.write("<h1>PicketLink OIDC Authorization Server</h1>");
        writer.write("<p>Demo user: <code>" + OidcDemoConstants.DEMO_USERNAME + "</code> / <code>"
                + OidcDemoConstants.DEMO_PASSWORD + "</code></p>");
        writer.write("<form method=\"post\" action=\"" + req.getContextPath() + "/j_security_check\">");
        writer.write("<label>Username <input name=\"j_username\" value=\"" + OidcDemoConstants.DEMO_USERNAME
                + "\"/></label><br/>");
        writer.write("<label>Password <input type=\"password\" name=\"j_password\" value=\""
                + OidcDemoConstants.DEMO_PASSWORD + "\"/></label><br/>");
        writer.write("<button type=\"submit\">Login</button></form>");
        writer.write("<p><a href=\"" + req.getContextPath() + "/app/admin\">Back to admin UI</a></p>");
        writer.write("</body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }
}
