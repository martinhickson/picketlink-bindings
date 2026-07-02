package org.picketlink.demo.sp;

import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.picketlink.demo.shared.DemoInfoResource;
import jakarta.servlet.ServletConfig;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import java.util.LinkedHashMap;
import java.util.Map;

public class SpCxfServlet extends CXFNonSpringServlet {

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        String baseUrl = servletConfig.getServletContext().getInitParameter("demo.base.url");
        Map<String, String> links = new LinkedHashMap<>();
        links.put("home", baseUrl + "app/");
        links.put("securedApp", baseUrl + "app/secured");
        links.put("admin", baseUrl + "app/admin");
        links.put("metadataXml", baseUrl + "metadata");
        links.put("metadataJson", baseUrl + "api/admin/federation/metadata");
        links.put("idpHome", servletConfig.getServletContext().getInitParameter("demo.idp.base.url") + "app/");

        JAXRSServerFactoryBean factory = new JAXRSServerFactoryBean();
        factory.setBus(getBus());
        factory.setServiceBean(new DemoInfoResource("SP", baseUrl, links));
        factory.setAddress("/");
        factory.create();
    }
}
