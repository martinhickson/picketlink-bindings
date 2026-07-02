package org.picketlink.test.wildfly36idm.deployment;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.IdentityQueryBuilder;

import java.util.List;

@ApplicationScoped
public class IdmUserService {

    @Inject
    private IdmBootstrap bootstrap;

    @Transactional
    public void createUser(String loginName) {
        IdentityManager identityManager = bootstrap.identityManager();
        User existing = findUser(identityManager, loginName);
        if (existing != null) {
            identityManager.remove(existing);
        }

        User user = new User(loginName);
        identityManager.add(user);
    }

    @Transactional
    public boolean userExists(String loginName) {
        return findUser(bootstrap.identityManager(), loginName) != null;
    }

    private User findUser(IdentityManager identityManager, String loginName) {
        IdentityQueryBuilder queryBuilder = identityManager.getQueryBuilder();
        List<User> users = queryBuilder.createIdentityQuery(User.class)
                .where(queryBuilder.equal(User.LOGIN_NAME, loginName))
                .getResultList();
        return users.isEmpty() ? null : users.get(0);
    }
}
