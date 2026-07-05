# WildFly 36 IDM Integration Tests

Arquillian integration tests for PicketLink IDM using the JPA identity store and
WildFly's default `ExampleDS` datasource on **WildFly 36**.

Uses HTTP port **8580** (port-offset 500) so it can run alongside `wildfly36-it` (8180)
and `wildfly36-jaas-it` (8380).

## Prerequisites

Install the PicketLink reactor (including IDM modules) into the local Maven repository:

```bash
cd picketlink
mvn install -Dcheckstyle.skip=true -pl modules/common,modules/config,modules/idm -am
```

## Run

```bash
cd picketlink-bindings
mvn verify -Pwildfly36-idm-it -pl picketlink-wildfly-common/wildfly36-idm-it
```

The test deploys a thin WAR that bootstraps `IdentityManager` with the simple JPA schema
via CDI and exposes HTTP endpoints to create and look up users.
