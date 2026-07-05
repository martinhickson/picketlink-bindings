# PicketLink WildFly 36 OIDC Demo

Dual WildFly 36 setup demonstrating **OpenID Connect Authorization Code flow** using Apache CXF OIDC/OAuth2:

| Host | Role | Context |
|------|------|---------|
| `127.0.0.102` | OIDC **Authorization Server** (token producer) | `/demo-as` |
| `127.0.0.101` | OIDC **Relying Party** (consumer) | `/demo-rp` |

## Build & run

From `picketlink-bindings`:

```bash
mvn -Pwildfly36-oidc-demo -pl picketlink-wildfly-common/wildfly-36-oidc-demo -am verify \
  -Dpicketlink.version=2.5.5.jdk17.1
```

Keep servers running after IT:

```bash
mvn -Pwildfly36-oidc-demo,demo-keep-alive -pl picketlink-wildfly-common/wildfly-36-oidc-demo -am verify \
  -Dpicketlink.version=2.5.5.jdk17.1 -Ddemo.keep.alive=true
```

Stop:

```bash
pkill -f 'wildfly-36-oidc-demo/demo-it/target/wildfly'
```

## URLs

- AS discovery: http://127.0.0.102:8080/demo-as/.well-known/openid-configuration
- AS admin UI: http://127.0.0.102:8080/demo-as/app/admin (requires `adminUiEnabled=true` on `VirtualResourcesServlet` in `demo-as-war` `web.xml`; enabled in the demo)
- RP secured UI: http://127.0.0.101:8080/demo-rp/app/secured
- Login: `user1` / `password1` (at AS during authorize)

## Architecture

```
picketlink/modules/oidc/          picketlink-oidc (CXF OIDC bootstrap + OidcKeyAdminResource at /api/keys)
  └── oidc-admin-ui/              Angular 22 AS admin SPA (packaged in picketlink-oidc JAR)
picketlink/modules/auth/          picketlink-auth (VirtualResourcesServlet for admin UI static assets)
wildfly-36-oidc-demo/
├── demo-as-war/                  Authorization Server WAR (OidcAuthorizationCodeService, token, JWKS)
├── demo-rp-war/                  Relying Party WAR (OidcClientCodeRequestFilter + /api/me)
├── demo-oidc-shared/             Shared servlets + DemoOidcMeResource
├── rp-ui/                        Angular RP SPA (SpaFallbackServlet at /app/*)
└── demo-it/                      Dual WildFly launcher + IT
```

Flow: RP Angular guard → `GET /api/me` → CXF `OidcClientCodeRequestFilter` → redirect to AS `/oidc/authorize` → FORM login → code → token + id_token → `/api/me` returns authenticated user.
