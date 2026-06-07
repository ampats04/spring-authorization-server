package com.company.authserver.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@Component
@Profile("prod")
@ConfigurationProperties(prefix = "app.azure")
public class AzureProperties {

    private static final String UUID_PATTERN =
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    @NotBlank(message = "Azure Key Vault URL must not be blank")
    @Pattern(
            regexp = "^https://[\\w-]+\\.vault\\.azure\\.net/?$",
            message = "vaultUrl must be a valid Azure Key Vault HTTPS URL"
    )
    private String vaultUrl;

    @NotBlank(message = "Signing key secret name must not be blank")
    private String signingKeySecretName;

    @NotBlank(message = "Signing public key secret name must not be blank")
    private String signingPublicKeySecretName;

    @Valid
    @NotNull(message = "Azure credentials block must be configured")
    private Credentials credentials = new Credentials();

    @Data
    public static class Credentials {

        @NotBlank(message = "Azure client ID must not be blank")
        @Pattern(regexp = UUID_PATTERN, message = "clientId must be a valid UUID")
        private String clientId;

        @NotBlank(message = "Azure client secret must not be blank")
        private String clientSecret;

        @NotBlank(message = "Azure tenant ID must not be blank")
        @Pattern(regexp = UUID_PATTERN, message = "tenantId must be a valid UUID")
        private String tenantId;
    }
}
