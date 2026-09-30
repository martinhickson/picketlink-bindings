/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2026 PicketLink contributors.
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
package org.picketlink.identity.federation.bindings.wildfly.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.Subject;

import org.junit.Test;

public class UndertowRoleGeneratorTestCase {

    @Test
    public void declaredPrincipalRolesWin() {
        PicketLinkUndertowPrincipal principal = new PicketLinkUndertowPrincipal(
                "ukbroker1", Arrays.asList("sonata-web"));
        List<String> roles = new UndertowRoleGenerator().generateRoles(principal);
        assertEquals(Arrays.asList("sonata-web"), roles);
    }

    @Test
    public void subjectRolesGroupIsReadByMembers() {
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolesGroup(Arrays.asList("sonata-agent", "sonata-staff")));
        List<String> roles = new ArrayList<String>();
        UndertowRoleGenerator.addRolesGroup(roles, subject);
        assertEquals(Arrays.asList("sonata-agent", "sonata-staff"), roles);
    }

    @Test
    public void noIdentityYieldsNoRoles() {
        List<String> roles = new UndertowRoleGenerator().generateRoles(new Principal() {
            @Override
            public String getName() {
                return "ukbroker1";
            }
        });
        assertTrue(roles.isEmpty());
    }

    public static final class RolesGroup implements Principal {
        private final List<Principal> members = new ArrayList<Principal>();

        RolesGroup(List<String> names) {
            for (final String name : names) {
                members.add(new Principal() {
                    @Override
                    public String getName() {
                        return name;
                    }
                });
            }
        }

        @Override
        public String getName() {
            return "Roles";
        }

        public Enumeration<? extends Principal> members() {
            return Collections.enumeration(members);
        }
    }
}
