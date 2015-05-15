/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.identity.federation.bindings.wildfly.sp;

import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.util.StringUtil;
import org.picketlink.config.federation.IdentityURLProviderType;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.web.config.IdentityURLConfigurationProvider;
import org.picketlink.identity.federation.web.config.PropertiesIdentityURLProvider;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Pedro Igor
 */
public class IdentityURLProviderHandler implements HttpHandler {

    protected static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    public static final String ACCOUNT_CHOOSER_COOKIE_NAME = "picketlink.account.name";
    public static final String ACCOUNT_PARAMETER = "idp";
    public static final String AUTHENTICATING = "AUTHENTICATING";
    public static final String STATE = "STATE";

    public static final HandlerWrapper wrapper(final SPType spType, final ServletContext servletContext) {
        return new HandlerWrapper() {
            @Override
            public HttpHandler wrap(HttpHandler next) {
                return new IdentityURLProviderHandler(spType, servletContext, next);
            }
        };
    }

    private final HttpHandler next;
    private final SPType spType;
    private final IdentityURLConfigurationProvider identityURLConfigurationProvider;
    private final Map<String, String> idpMap = new ConcurrentHashMap<String, String>();

    public IdentityURLProviderHandler(SPType spType, ServletContext servletContext, HttpHandler next) {
        this.spType = spType;
        this.next = next;

        IdentityURLProviderType identityURLProvider = spType.getIdentityURLProvider();

        if (identityURLProvider == null) {
            throw logger.nullArgumentError("IdentityURL Provider");
        }

        try {
            String type = identityURLProvider.getType();

            if (type == null) {
                type = PropertiesIdentityURLProvider.class.getName();
            }

            Class<?> clazz = SecurityActions.loadClass(getClass(), type);

            if (clazz == null) {
                throw logger.classNotLoadedError(type);
            }

            this.identityURLConfigurationProvider = (IdentityURLConfigurationProvider) clazz.newInstance();
            this.identityURLConfigurationProvider.setServletContext(servletContext);
            this.idpMap.putAll(identityURLConfigurationProvider.getIDPMap());
        } catch (Exception e) {
            throw new RuntimeException("Could not create Identity URL provider [" + getClass().getName() + "].", e);
        }
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();
        HttpSession session = request.getSession();

        if(idpMap.isEmpty()){
            idpMap.putAll(identityURLConfigurationProvider.getIDPMap());
        }

        String sessionState = (String) session.getAttribute(STATE);
        String idpChosenKey = request.getParameter(ACCOUNT_PARAMETER);
        String cookieValue = cookieValue(request);

        if (cookieValue != null || AUTHENTICATING.equals(sessionState)) {
            if(idpChosenKey != null){
                String chosenIDP = idpMap.get(idpChosenKey);
                request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
            }

            // Case when user is directed to IDP and wants to change the IDP. So he enters the URL again
            if (AUTHENTICATING.equals(sessionState) && request.getParameter(GeneralConstants.SAML_RESPONSE_KEY) == null) {
                session.removeAttribute(STATE);
                redirectToChosenPage(request, response);
                return;
            }
            proceedToAuthentication(exchange, cookieValue);
        } else {
            if (idpChosenKey != null) {
                String chosenIDP = idpMap.get(idpChosenKey);
                if (chosenIDP != null) {
                    request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                    session.setAttribute(STATE, AUTHENTICATING);
                    proceedToAuthentication(exchange, idpChosenKey);
                }else {
                    logger.configurationFileMissing(":IDP Mapping");
                    throw new ServletException();
                }
            } else {
                // redirect to provided html
                //saveRequest(request, request.getSessionInternal());
                redirectToChosenPage(request, response);
                exchange.endExchange();
            }
        }
    }

    protected String cookieValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String cookieName = cookie.getName();
                String cookieDomain = cookie.getDomain();
                if (cookieDomain != null && cookieDomain.equalsIgnoreCase(getIdentityURLProvider().getDomain())) {
                    // Found a cookie with the same domain name
                    if (ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        String cookieValue = cookie.getValue();
                        String chosenIDP = idpMap.get(cookieValue);
                        if (chosenIDP != null) {
                            request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                            return cookieValue;
                        }
                    }
                }else{
                    if (ACCOUNT_CHOOSER_COOKIE_NAME.equals(cookieName)) {
                        // Found cookie
                        String cookieValue = cookie.getValue();
                        String chosenIDP = idpMap.get(cookieValue);
                        if (chosenIDP != null) {
                            request.setAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP, chosenIDP);
                            return cookieValue;
                        }
                    }
                }
            }
        }
        return null;
    }

    protected void redirectToChosenPage(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String page = getIdentityURLProvider().getPage();

        if (page == null) {
            page = "/accountChooser.html";
        }

        ServletContext servletContext = request.getServletContext();
        RequestDispatcher requestDispatcher = servletContext.getRequestDispatcher(page);

        if (requestDispatcher != null) {
            requestDispatcher.forward(request, response);
        }
    }

    protected void proceedToAuthentication(HttpServerExchange exchange, String cookieValue) throws Exception {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = (HttpServletRequest) servletRequestContext.getServletRequest();
        HttpServletResponse response = (HttpServletResponse) servletRequestContext.getServletResponse();
        HttpSession session = request.getSession(true);
        String state = session != null ? (String) session.getAttribute(STATE) : null;

        try {
            this.next.handleRequest(exchange);
        } finally {
            //If we are authenticated and registered at the service provider
            if (request.getUserPrincipal() != null && StringUtil.isNotNull(state)) {
                session.removeAttribute(STATE);
                // Send back a cookie
                ServletContext servletContext = request.getServletContext();
                String contextpath = servletContext.getContextPath();

                if (cookieValue == null) {
                    cookieValue = request.getParameter(ACCOUNT_PARAMETER);
                }

                Cookie cookie = new Cookie(ACCOUNT_CHOOSER_COOKIE_NAME, cookieValue);

                cookie.setPath(contextpath);

                IdentityURLProviderType identityURLProvider = getIdentityURLProvider();
                cookie.setMaxAge(identityURLProvider.getExpiration());

                String domain = identityURLProvider.getDomain();

                if (domain != null) {
                    cookie.setDomain(domain);
                }

                response.addCookie(cookie);
            }
        }

    }

    private IdentityURLProviderType getIdentityURLProvider() {
        return this.spType.getIdentityURLProvider();
    }
}
