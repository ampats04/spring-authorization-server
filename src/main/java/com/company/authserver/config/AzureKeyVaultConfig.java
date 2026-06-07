package com.company.authserver.config;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.company.authserver.properties.AzureProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Slf4j
@Configuration
@Profile("prod")
@RequiredArgsConstructor
public class AzureKeyVaultConfig {

    private final AzureProperties azure;

    @Bean
    public SecretClient secretClient() {
        log.info("Initializing Azure Key Vault SecretClient for vault: {}", azure.getVaultUrl());
        return new SecretClientBuilder()
                .vaultUrl(azure.getVaultUrl())
                .credential(credential())
                .buildClient();
    }

    private com.azure.core.credential.TokenCredential credential() {
        var creds = azure.getCredentials();
        return new ClientSecretCredentialBuilder()
                .clientId(creds.getClientId())
                .clientSecret(creds.getClientSecret())
                .tenantId(creds.getTenantId())
                .build();
    }
}
