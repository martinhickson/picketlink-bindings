package org.picketlink.test.wildfly36idm.deployment;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.picketlink.idm.jpa.internal.JPAIdentityStore;
import org.picketlink.idm.spi.ContextInitializer;
import org.picketlink.idm.spi.IdentityContext;
import org.picketlink.idm.spi.IdentityStore;

@ApplicationScoped
public class WildFlyJpaContextInitializer implements ContextInitializer {

    @PersistenceContext(unitName = "picketlink-idm-it")
    private EntityManager entityManager;

    @Override
    public void initContextForStore(IdentityContext ctx, IdentityStore<?> store) {
        if (store instanceof JPAIdentityStore) {
            ctx.setParameter(JPAIdentityStore.INVOCATION_CTX_ENTITY_MANAGER, entityManager);
        }
    }
}
