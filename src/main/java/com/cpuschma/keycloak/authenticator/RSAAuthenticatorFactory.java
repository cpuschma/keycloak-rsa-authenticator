package com.cpuschma.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for RSA Authenticator that provides configuration and lifecycle management.
 * This authenticator is used to authenticate users with RSA providers via RADIUS protocol.
 */
public class RSAAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "keycloak-rsa-authenticator";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    // Factory methods

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new RSAAuthenticator();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    // Display and metadata methods

    @Override
    public String getDisplayType() {
        return "RSA Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "Authenticator";
    }

    @Override
    public String getHelpText() {
        return "This authenticator is used to authenticate with RSA providers";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                RSAAuthenticatorProperties.SERVER_LIST,
                RSAAuthenticatorProperties.REQUIRED_ROLE_NAME,
                RSAAuthenticatorProperties.MINIMUM_CODE_LENGTH,
                RSAAuthenticatorProperties.MAXIMUM_CODE_LENGTH,
                RSAAuthenticatorProperties.LOGIN_FAILURE_MESSAGE,
                RSAAuthenticatorProperties.RADIUS_SECRET
        );
    }

    // Lifecycle methods

    @Override
    public void init(Config.Scope scope) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No resources to clean up
    }
}