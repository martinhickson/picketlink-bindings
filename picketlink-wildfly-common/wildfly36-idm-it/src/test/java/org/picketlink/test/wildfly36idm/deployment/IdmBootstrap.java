package org.picketlink.test.wildfly36idm.deployment;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.jpa.model.sample.simple.AccountTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.AttributeTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.DigestCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.GroupTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.IdentityTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.OTPCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.PartitionTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.PasswordCredentialTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RelationshipIdentityTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RelationshipTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.RoleTypeEntity;
import org.picketlink.idm.jpa.model.sample.simple.X509CredentialTypeEntity;
import org.picketlink.idm.model.Relationship;
import org.picketlink.idm.model.basic.Realm;

@ApplicationScoped
public class IdmBootstrap {

    public static final String STORE_NAME = "WILDFLY_JPA_STORE";

    @Inject
    private WildFlyJpaContextInitializer jpaContextInitializer;

    private DefaultPartitionManager partitionManager;

    @PostConstruct
    void init() {
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();
        builder.named(STORE_NAME)
                .stores()
                .jpa()
                .mappedEntity(
                        PartitionTypeEntity.class,
                        AccountTypeEntity.class,
                        RoleTypeEntity.class,
                        GroupTypeEntity.class,
                        IdentityTypeEntity.class,
                        RelationshipTypeEntity.class,
                        RelationshipIdentityTypeEntity.class,
                        PasswordCredentialTypeEntity.class,
                        DigestCredentialTypeEntity.class,
                        X509CredentialTypeEntity.class,
                        OTPCredentialTypeEntity.class,
                        AttributeTypeEntity.class)
                .supportGlobalRelationship(Relationship.class)
                .addContextInitializer(jpaContextInitializer)
                .supportAllFeatures();

        partitionManager = new DefaultPartitionManager(builder.buildAll());

        if (partitionManager.getPartition(Realm.class, Realm.DEFAULT_REALM) == null) {
            partitionManager.add(new Realm(Realm.DEFAULT_REALM));
        }
    }

    public IdentityManager identityManager() {
        return partitionManager.createIdentityManager();
    }
}
