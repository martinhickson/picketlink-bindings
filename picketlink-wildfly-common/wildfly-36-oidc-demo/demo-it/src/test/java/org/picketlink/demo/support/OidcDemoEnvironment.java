package org.picketlink.demo.support;

public final class OidcDemoEnvironment {

    public static final String AS_HOST = prop("demo.as.host", "127.0.0.102");
    public static final String RP_HOST = prop("demo.rp.host", "127.0.0.101");
    public static final int HTTP_PORT = intProp("demo.http.port", 8080);
    public static final int MGMT_PORT = intProp("demo.mgmt.port", 9990);
    public static final String AS_JBOSS_HOME = prop("demo.as.jboss.home", "target/wildfly-as");
    public static final String RP_JBOSS_HOME = prop("demo.rp.jboss.home", "target/wildfly-rp");
    public static final int KEEP_ALIVE_MINUTES = intProp("demo.keep.alive.minutes", 30);
    public static final boolean KEEP_ALIVE = Boolean.parseBoolean(prop("demo.keep.alive", "false"));

    public static String asBaseUrl() {
        return "http://" + AS_HOST + ":" + HTTP_PORT + "/demo-as/";
    }

    public static String rpBaseUrl() {
        return "http://" + RP_HOST + ":" + HTTP_PORT + "/demo-rp/";
    }

    public static String asAppUrl() {
        return asBaseUrl() + "app/";
    }

    public static String rpAppUrl() {
        return rpBaseUrl() + "app/";
    }

    private OidcDemoEnvironment() {
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
