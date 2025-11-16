package com.cpuschma.keycloak.authenticator;

import org.keycloak.provider.ProviderConfigProperty;

/**
 * Configuration properties for RSA Authenticator.
 * Contains all configurable settings required for RSA RADIUS authentication.
 */
public class RSAAuthenticatorProperties {
    // Common property prefix to maintain consistency
    private static final String RSA_PREFIX = "rsa";

    // Property types for reuse
    private static final String STRING_TYPE = ProviderConfigProperty.STRING_TYPE;
    private static final String MULTIVALUED_STRING_TYPE = ProviderConfigProperty.MULTIVALUED_STRING_TYPE;
    private static final String INTEGER_TYPE = "Integer"; // INTEGER_TYPE not available in ProviderConfigProperty

    // RADIUS server configuration
    public static final ProviderConfigProperty SERVER_LIST = createProperty(
            "ServerList",
            "RSA RADIUS Server List",
            "List of RADIUS servers separated by comma (ip:port)",
            MULTIVALUED_STRING_TYPE,
            null,
            false,
            true);

    public static final ProviderConfigProperty RADIUS_SECRET = createProperty(
            "RadiusSecret",
            "RADIUS Secret",
            "Secret used to authenticate with the RADIUS server(s)",
            STRING_TYPE,
            null,
            true,
            false);

    // User and access configuration
    public static final ProviderConfigProperty REQUIRED_ROLE_NAME = createProperty(
            "RequiredRoleName",
            "Required Role Name",
            "If set, user must have this role to be eligible for RSA authentication",
            STRING_TYPE,
            "",
            false,
            false);

    // Code validation configuration
    public static final ProviderConfigProperty MINIMUM_CODE_LENGTH = createProperty(
            "MinimumCodeLength",
            "Minimum Code Length",
            "Sets the minimum length of the RSA code",
            INTEGER_TYPE,
            8,
            false,
            true);

    public static final ProviderConfigProperty MAXIMUM_CODE_LENGTH = createProperty(
            "MaximumCodeLength",
            "Maximum Code Length",
            "Sets the maximum length of the RSA code",
            INTEGER_TYPE,
            8,
            false,
            true);

    // Error message configuration
    public static final ProviderConfigProperty LOGIN_FAILURE_MESSAGE = createProperty(
            "LoginFailureMessage",
            "Login Failure Message",
            "Message shown to the user when RSA authentication fails",
            STRING_TYPE,
            "Invalid RSA code",
            false,
            true);

    /**
     * Helper method to create a property with consistent naming convention.
     */
    private static ProviderConfigProperty createProperty(
            String name,
            String label,
            String helpText,
            String type,
            Object defaultValue,
            boolean secret,
            boolean required) {
        return new ProviderConfigProperty(
                RSA_PREFIX + name,
                label,
                helpText,
                type,
                defaultValue,
                secret,
                required);
    }
}