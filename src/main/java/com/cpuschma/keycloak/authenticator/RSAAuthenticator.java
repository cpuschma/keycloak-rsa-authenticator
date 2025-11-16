package com.cpuschma.keycloak.authenticator;

import jakarta.ws.rs.core.Response;
import org.aaa4j.radius.client.RadiusClient;
import org.aaa4j.radius.client.RadiusClientException;
import org.aaa4j.radius.core.attribute.StringData;
import org.aaa4j.radius.core.attribute.TextData;
import org.aaa4j.radius.core.attribute.attributes.MessageAuthenticator;
import org.aaa4j.radius.core.attribute.attributes.UserName;
import org.aaa4j.radius.core.attribute.attributes.UserPassword;
import org.aaa4j.radius.core.packet.Packet;
import org.aaa4j.radius.core.packet.packets.AccessAccept;
import org.aaa4j.radius.core.packet.packets.AccessRequest;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(RSAAuthenticator.class);
    private static final String TPL_CODE = "rsa-authenticator-form.ftl";
    private static final String ERROR_CONFIG_MISSING = "RSA Server not configured";
    private static final String ERROR_OTP_MISSING = "Please enter your RSA code";
    private static final String ERROR_RADIUS_FAILURE = "RSA Authentication not configured.";
    private static final String OTP_FORM_FIELD = "otp";
    private static final String ERROR_REASON = "invalid_credentials";
    private static final String ERROR_CODE = "invalid_rsa_code";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RSAAuthenticatorConfig config = validateConfiguration(context);
        if (config == null) {
            return;
        }

        UserModel user = context.getUser();
        if (user == null) {
            context.success();
            return;
        }

        if (isUserEligibleForRSA(user, config)) {
            LOG.debugf("User %s has required role %s", user.getUsername(), config.getRequiredRoleName());
            displayRSAChallenge(context);
        } else {
            LOG.debugf("User %s has not required role %s", user.getUsername(), config.getRequiredRoleName());
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        RSAAuthenticatorConfig config = validateConfiguration(context);
        if (config == null) {
            return;
        }

        UserModel user = context.getUser();
        String otpCode = context.getHttpRequest().getDecodedFormParameters().getFirst(OTP_FORM_FIELD);

        if (otpCode == null || otpCode.isEmpty()) {
            handleAuthenticationFailure(context, ERROR_OTP_MISSING);
            return;
        }

        try {
            if (createAndSubmitRadiusRequest(context, user, otpCode, config)) {
                return;
            }
        } catch (Exception e) {
            LOG.error("Error processing RADIUS request", e);
        }

        handleAuthenticationFailure(context, ERROR_RADIUS_FAILURE);
    }

    private boolean createAndSubmitRadiusRequest(AuthenticationFlowContext context,
                                                 UserModel user,
                                                 String otpCode,
                                                 RSAAuthenticatorConfig config) {
        AccessRequest accessRequest = new AccessRequest(List.of(
                new MessageAuthenticator(),
                new UserName(new TextData(user.getUsername())),
                new UserPassword(new StringData(otpCode.getBytes(UTF_8)))
        ));

        for (RadiusClient server : config.getServerList()) {
            LOG.debugf("Sending RADIUS Access Request for user %s", user.getUsername());
            try {
                Packet responsePacket = server.send(accessRequest);
                if (responsePacket instanceof AccessAccept) {
                    context.success();
                } else {
                    handleAuthenticationFailure(context, config.getLoginFailureMessage());
                }
                return true;
            } catch (RadiusClientException e) {
                LOG.warnf("RADIUS server error: %s", e.getMessage());
                // Continue to next server
            }
        }
        return false;
    }

    private RSAAuthenticatorConfig validateConfiguration(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null || authenticatorConfig.getConfig() == null) {
            handleAuthenticationFailure(context, ERROR_CONFIG_MISSING);
            return null;
        }
        return new RSAAuthenticatorConfig(authenticatorConfig.getConfig());
    }

    private boolean isUserEligibleForRSA(UserModel user, RSAAuthenticatorConfig config) {
        return config.getRequiredRoleName().isEmpty() ||
                user.getRoleMappingsStream().anyMatch(role -> role.getName().equals(config.getRequiredRoleName()));
    }

    private void displayRSAChallenge(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        Response response = form.createForm(TPL_CODE);
        context.challenge(response);
    }

    private void handleAuthenticationFailure(AuthenticationFlowContext context, String message) {
        UserModel user = context.getUser();
        context.getEvent()
                .event(EventType.LOGIN_ERROR)
                .realm(context.getRealm())
                .client(context.getAuthenticationSession().getClient().getClientId())
                .user(user)
                .detail(Details.USERNAME, user.getUsername())
                .detail(Details.REASON, ERROR_REASON)
                .error(ERROR_CODE);

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form().setError(message).createForm(TPL_CODE));
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Unfortunately we don't have access to the authenticator configuration yet
        // to determine whether the user has the required role
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No actions required
    }

    @Override
    public void close() {
        // No resources to close
    }
}