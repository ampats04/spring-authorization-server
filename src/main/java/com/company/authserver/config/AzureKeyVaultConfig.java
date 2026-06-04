package com.company.authserver.config;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.company.authserver.properties.AzureProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Wires the Azure SDK clients used when running with the 'azure' profile.
 * Swap DefaultAzureCredential for ClientSecretCredential so the vault-url /
 * client-id / secret / tenant-id from application.yml are honoured explicitly.
 */
@Configuration
@Profile("azure")
@RequiredArgsConstructor
public class AzureKeyVaultConfig {

    private final AzureProperties azure;

    @Bean
    public SecretClient secretClient() {
        return new SecretClientBuilder()
                .vaultUrl(azure.getVaultUrl())
                .credential(credential())
                .buildClient();
    }

    @Bean
    public CryptographyClient cryptographyClient() {
        return new CryptographyClientBuilder()
                .keyIdentifier(azure.getSigningKeyId())
                .credential(credential())
                .buildClient();
    }

    private com.azure.core.credential.TokenCredential credential() {
        return new ClientSecretCredentialBuilder()
                .clientId(azure.getClientId())
                .clientSecret(azure.getClientSecret())
                .tenantId(azure.getTenantId())
                .build();
    }
}
