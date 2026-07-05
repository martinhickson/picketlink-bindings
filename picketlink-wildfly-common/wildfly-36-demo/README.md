# PicketLink WildFly 36 Dual-Server Demo

Runs **two WildFly 36 instances** for a full SAML SP / IDP setup:

| Role | Bind address | URL |
|------|--------------|-----|
| **IDP** | `127.0.0.102:8080` | http://127.0.0.102:8080/demo-idp/ |
| **SP** | `127.0.0.101:8080` | http://127.0.0.101:8080/demo-sp/ |

Each WAR includes an **Angular 19** SPA (standalone components + routing) and **Apache CXF JAX-RS** at `/api/info`, plus PicketLink metadata publishing at `/metadata` and `/api/admin/federation/metadata`.

## Prerequisites

Add loopback aliases (once per machine):

```bash
sudo ip addr add 127.0.0.101/8 dev lo
sudo ip addr add 127.0.0.102/8 dev lo
```

Build PicketLink federation + bindings first, then run the demo from this directory.

## Quick run (integration test)

```bash
cd picketlink-bindings
mvn -Pwildfly36-demo -pl picketlink-wildfly-common/wildfly-36-demo -am verify -Dpicketlink.version=2.5.5.jdk17.1
```

## Keep servers up for manual testing (30 minutes)

```bash
mvn -Pwildfly36-demo,demo-keep-alive -pl picketlink-wildfly-common/wildfly-36-demo -am verify \
  -Dpicketlink.version=2.5.5.jdk17.1 -Ddemo.keep.alive=true
```

The test prints a dashboard with links. Try:

1. **IDP UI** → http://127.0.0.102:8080/demo-idp/app/admin (metadata links)
2. **SP secured app** → http://127.0.0.101:8080/demo-sp/app/secured (SAML SSO)
3. Login at IDP with `user1` / `password1`

## Module layout

```
wildfly-36-demo/
├── demo-shared/      Shared servlets, CXF resource, role generator
├── demo-sp-war/      SP WAR + Angular build (sp-ui)
├── demo-idp-war/     IDP WAR + Angular build (idp-ui)
├── sp-ui/            Angular SPA for SP
├── idp-ui/           Angular SPA for IDP
├── demo-it/          Dual WildFly launcher + integration tests
```

## Customize hosts / keep-alive duration

```bash
-Ddemo.idp.host=127.0.0.102 \
-Ddemo.sp.host=127.0.0.101 \
-Ddemo.keep.alive.minutes=45
```
