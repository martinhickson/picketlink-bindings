package org.picketlink.demo.shared;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

public class FormLoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html;charset=UTF-8");
        Writer writer = resp.getWriter();
        writer.write("<!DOCTYPE html><html><head><title>IDP Login</title></head><body>");
        writer.write("<h1>PicketLink IDP Login</h1>");
        writer.write("<p>Demo user: <code>user1</code> / <code>password1</code></p>");
        writer.write("<form method=\"post\" action=\"" + req.getContextPath() + "/j_security_check\">");
        writer.write("<label>Username <input name=\"j_username\" value=\"user1\"/></label><br/>");
        writer.write("<label>Password <input type=\"password\" name=\"j_password\" value=\"password1\"/></label><br/>");
        writer.write("<button type=\"submit\">Login</button></form>");
        writer.write("<p><a href=\"" + req.getContextPath() + "/app/admin\">Back to admin UI</a></p>");
        writer.write("</body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }
}
