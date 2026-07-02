package org.picketlink.demo.support;

public final class DemoEnvironment {

    public static final String IDP_HOST = prop("demo.idp.host", "127.0.0.102");
    public static final String SP_HOST = prop("demo.sp.host", "127.0.0.101");
    public static final int HTTP_PORT = intProp("demo.http.port", 8080);
    public static final int MGMT_PORT = intProp("demo.mgmt.port", 9990);
    public static final String IDP_JBOSS_HOME = prop("demo.idp.jboss.home", "target/wildfly-idp");
    public static final String SP_JBOSS_HOME = prop("demo.sp.jboss.home", "target/wildfly-sp");
    public static final int KEEP_ALIVE_MINUTES = intProp("demo.keep.alive.minutes", 30);
    public static final boolean KEEP_ALIVE = Boolean.parseBoolean(prop("demo.keep.alive", "false"));

    public static String idpBaseUrl() {
        return "http://" + IDP_HOST + ":" + HTTP_PORT + "/demo-idp/";
    }

    public static String spBaseUrl() {
        return "http://" + SP_HOST + ":" + HTTP_PORT + "/demo-sp/";
    }

    public static String idpAppUrl() {
        return idpBaseUrl() + "app/";
    }

    public static String spAppUrl() {
        return spBaseUrl() + "app/";
    }

    private DemoEnvironment() {
    }

    private static String prop(String key, String defaultValue) {
        String value = System.getProperty(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int intProp(String key, int defaultValue) {
        String value = System.getProperty(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Integer.parseInt(value);
    }
}
