# Moved: OIDC admin UI

The authorization-server admin Angular app now lives in the PicketLink core module:

`picketlink/modules/oidc/oidc-admin-ui/`

It is built and packaged into `picketlink-oidc` at `META-INF/resources/oidc-admin-ui/` and served by `VirtualResourcesServlet` (from `picketlink-auth`) when `adminUiEnabled=true` is set in `web.xml`.
