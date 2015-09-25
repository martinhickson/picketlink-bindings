/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.picketlink.identity.federation.bindings.jboss.subject;

import java.security.Principal;
import org.jboss.security.CacheableManager;
import org.jboss.security.SecurityConstants;
import org.picketlink.identity.federation.bindings.tomcat.SubjectSecurityInteraction;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;

/**
 * An implementation of {@link SubjectSecurityInteraction} for JBoss AS 7.
 *
 * @author Anil.Saldhana@redhat.com
 * <a href="mailto:psilva@redhat.com">Pedro Silva</a>
 * @since Sep 13, 2011
 */
public class PicketLinkJBossSubjectInteraction implements SubjectSecurityInteraction {
    
    private String securityDomain;
    
    /**
     * @see SubjectSecurityInteraction#cleanup(Principal)
     */
    public boolean cleanup(Principal principal) {
        if (this.securityDomain != null && !"".equals(this.securityDomain)) {
            try {
                String lookupDomain = this.securityDomain;
                if (lookupDomain.startsWith(SecurityConstants.JAAS_CONTEXT_ROOT) == false)
                    lookupDomain = SecurityConstants.JAAS_CONTEXT_ROOT + "/" + lookupDomain;
                // lookup the JBossCachedAuthManager.
                InitialContext context = new InitialContext();
                CacheableManager manager = (CacheableManager) context.lookup(lookupDomain);
                // Flush the Authentication Cache
                manager.flushCache(principal);
            } catch (NamingException e) {
                throw new RuntimeException(e);
            }
        }

        return false;
    }

    /**
     * @see SubjectSecurityInteraction#get()
     */
    public Subject get() {
        try {
            return (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (PolicyContextException e) {
            throw new RuntimeException(e);
        }
    }

    public void setSecurityDomain(String securityDomain) {
        this.securityDomain = securityDomain;
    }
}