package org.picketlink.test.wildfly36.deployment;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import org.picketlink.identity.federation.bindings.wildfly.idp.UndertowRoleGenerator;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

/**
 * Elytron does not populate legacy {@code SecurityContextAssociation} subjects; delegate to
 * {@link UndertowRoleGenerator} first, then fall back to the IT test user mapping.
 */
public class TestRoleGenerator implements RoleGenerator {

    private final UndertowRoleGenerator delegate = new UndertowRoleGenerator();

    @Override
    public List<String> generateRoles(Principal principal) {
        List<String> roles = delegate.generateRoles(principal);
        if (!roles.isEmpty()) {
            return roles;
        }
        if (principal != null && "user1".equals(principal.getName())) {
            return Collections.singletonList("role1");
        }
        return Collections.emptyList();
    }
}
