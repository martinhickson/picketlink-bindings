package org.picketlink.demo.idp;

import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.picketlink.demo.shared.DemoInfoResource;
import jakarta.servlet.ServletConfig;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import java.util.LinkedHashMap;
import java.util.Map;

public class IdpCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String baseUrl = servletConfig.getServletContext().getInitParameter("demo.base.url");
        Map<String, String> links = new LinkedHashMap<>();
        links.put("home", baseUrl + "app/");
        links.put("admin", baseUrl + "app/admin");
        links.put("login", baseUrl + "FormLoginServlet");
        links.put("metadataXml", baseUrl + "metadata");
        links.put("metadataJson", baseUrl + "api/admin/federation/metadata");
        links.put("spHome", servletConfig.getServletContext().getInitParameter("demo.sp.base.url") + "app/");

        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(getBus());
        factory.setServiceBean(new DemoInfoResource("IDP", baseUrl, links));
        factory.setAddress("/");
        factory.create();
    }
}
