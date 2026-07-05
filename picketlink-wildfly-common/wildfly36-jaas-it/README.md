# WildFly 36 JAAS bridge integration tests

Parallel to `wildfly36-it`, this module verifies the **`jaas-bridge`** Elytron identity strategy:

```xml
<context-param>
    <param-name>org.picketlink.elytron.identity.strategy</param-name>
    <param-value>jaas-bridge</param-value>
</context-param>
```

SP WARs also configure `org.picketlink.jaas.login.entry=PicketLinkSP`, backed by `SAML2LoginModule` via
`java.security.auth.login.config` (see `ElytronTestSetup.writeSpJaasConfig()`).

## Run

```bash
mvn verify -Pwildfly36-jaas-it -pl picketlink-wildfly-common/wildfly36-jaas-it
```

Uses HTTP port **8380** (WildFly port-offset 300) so it can run independently of `wildfly36-it` (8180).

## Tests

| Test | Description |
|------|-------------|
| `IdpDeploymentIT` | IdP form login challenge |
| `SPInitiatedRedirectBindingIT` | SP-initiated SSO, redirect binding, jaas-bridge |
| `SPInitiatedPostBindingIT` | SP-initiated SSO, POST binding, jaas-bridge |

Deployment pattern matches `wildfly36-it`: all PicketLink JARs in `org.picketlink` module, thin WARs via `jboss-deployment-structure.xml`.
