package org.picketlink.demo.shared;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import org.picketlink.identity.federation.bindings.wildfly.idp.UndertowRoleGenerator;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

public class DemoRoleGenerator implements RoleGenerator {

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
