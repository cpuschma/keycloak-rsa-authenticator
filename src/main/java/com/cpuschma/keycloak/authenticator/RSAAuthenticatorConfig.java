package com.cpuschma.keycloak.authenticator;

import org.aaa4j.radius.client.RadiusClient;
import org.aaa4j.radius.client.clients.UdpRadiusClient;

import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class RSAAuthenticatorConfig {
    // Configuration keys
    private static final String CONFIG_REQUIRED_ROLE = "rsaRequiredRoleName";
    private static final String CONFIG_MIN_CODE_LENGTH = "rsaMinimumCodeLength";
    private static final String CONFIG_MAX_CODE_LENGTH = "rsaMaximumCodeLength";
    private static final String CONFIG_FAILURE_MESSAGE = "rsaLoginFailureMessage";
    private static final String CONFIG_RADIUS_SECRET = "rsaRadiusSecret";
    private static final String CONFIG_SERVER_LIST = "rsaServerList";
    private static final String SERVER_DELIMITER = "##";
    private static final String ADDRESS_PORT_DELIMITER = ":";

    // Default values
    private static final int DEFAULT_MIN_CODE_LENGTH = 6;
    private static final int DEFAULT_MAX_CODE_LENGTH = 8;
    private static final String DEFAULT_FAILURE_MESSAGE = "Authentication failed";

    private final List<RadiusClient> serverList;
    private final String radiusSecret;
    private final String requiredRoleName;
    private final int minimumCodeLength;
    private final int maximumCodeLength;
    private final String loginFailureMessage;

    public RSAAuthenticatorConfig(Map<String, String> config) {
        Objects.requireNonNull(config, "Configuration map cannot be null");

        this.requiredRoleName = config.getOrDefault(CONFIG_REQUIRED_ROLE, "");
        this.radiusSecret = Objects.requireNonNull(
                config.get(CONFIG_RADIUS_SECRET),
                "RADIUS secret is required"
        );

        this.minimumCodeLength = parseIntWithDefault(
                config.get(CONFIG_MIN_CODE_LENGTH),
                DEFAULT_MIN_CODE_LENGTH
        );
        this.maximumCodeLength = parseIntWithDefault(
                config.get(CONFIG_MAX_CODE_LENGTH),
                DEFAULT_MAX_CODE_LENGTH
        );
        this.loginFailureMessage = config.getOrDefault(
                CONFIG_FAILURE_MESSAGE,
                DEFAULT_FAILURE_MESSAGE
        );

        this.serverList = Collections.unmodifiableList(createServerList(config));
    }

    private List<RadiusClient> createServerList(Map<String, String> config) {
        String serverListConfig = config.get(CONFIG_SERVER_LIST);
        if (serverListConfig == null || serverListConfig.isEmpty()) {
            return Collections.emptyList();
        }

        List<RadiusClient> clients = new ArrayList<>();
        String[] serverAddresses = serverListConfig.split(SERVER_DELIMITER);

        for (String serverAddress : serverAddresses) {
            clients.add(createRadiusClient(serverAddress));
        }

        return clients;
    }

    private RadiusClient createRadiusClient(String serverAddress) {
        String[] parts = serverAddress.split(ADDRESS_PORT_DELIMITER);
        if (parts.length != 2) {
            throw new IllegalArgumentException(
                    "Invalid server address format: " + serverAddress +
                            ". Expected format: ip:port"
            );
        }

        String ipAddress = parts[0];
        int port = Integer.parseInt(parts[1]);

        return UdpRadiusClient.newBuilder()
                .secret(radiusSecret.getBytes(UTF_8))
                .address(new InetSocketAddress(ipAddress, port))
                .build();
    }

    private int parseIntWithDefault(String value, int defaultValue) {
        try {
            return value != null ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public List<RadiusClient> getServerList() {
        return serverList;
    }

    public String getRadiusSecret() {
        return radiusSecret;
    }

    public String getRequiredRoleName() {
        return requiredRoleName;
    }

    public int getMinimumCodeLength() {
        return minimumCodeLength;
    }

    public int getMaximumCodeLength() {
        return maximumCodeLength;
    }

    public String getLoginFailureMessage() {
        return loginFailureMessage;
    }
}