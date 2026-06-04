package com.company.authserver.store;

import com.azure.security.keyvault.secrets.SecretClient;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

/**
 * Retrieves client secrets from Azure Key Vault.
 * Secret naming convention: "client-{clientId}"
 *
 * Security note (ref 8.8): consider mapping clientId to an opaque UUID as the
 * Key Vault secret name to prevent enumeration if an attacker gains partial vault access.
 */
@Component
@Profile("azure")
@RequiredArgsConstructor
public class KeyVaultClientSecretStore implements ClientSecretStore {

    private final SecretClient secretClient;

    @Override
    public String getHashedSecret(String clientId) {
        try {
            return secretClient.getSecret("client-" + clientId).getValue();
        } catch (Exception ex) {
            // Never expose Key Vault error details externally (ref 8.3)
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}
