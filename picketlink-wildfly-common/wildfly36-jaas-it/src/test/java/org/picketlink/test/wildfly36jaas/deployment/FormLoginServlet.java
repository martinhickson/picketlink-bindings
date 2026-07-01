package org.picketlink.test.wildfly36jaas.deployment;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

public class FormLoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html");
        Writer writer = resp.getWriter();
        writer.write("Login Page");
        writer.write("<form id=\"login_form\" name=\"login_form\" method=\"post\""
                + " action=\"" + req.getContextPath() + "/j_security_check\""
                + " enctype=\"application/x-www-form-urlencoded\">"
                + "<div style=\"margin-left: 15px;\">"
                + "<p><label for=\"username\"> Username</label><br />"
                + "<input id=\"username\" type=\"text\" name=\"j_username\" size=\"20\" /></p>"
                + "<p><label for=\"password\"> Password</label><br />"
                + "<input id=\"password\" type=\"password\" name=\"j_password\" value=\"\" size=\"20\" /></p>"
                + "<center><input id=\"submit\" type=\"submit\" name=\"submit\" value=\"Login\" class=\"buttonmed\" />"
                + "</center></div></form>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }
}
