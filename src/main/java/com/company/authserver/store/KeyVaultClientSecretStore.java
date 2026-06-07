package com.company.authserver.store;

import com.azure.security.keyvault.secrets.SecretClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
@Component
@Profile("prod")
@RequiredArgsConstructor
public class KeyVaultClientSecretStore implements ClientSecretStore {

    private final SecretClient secretClient;

    @Override
    public String getHashedSecret(String clientId) {
        log.debug("Fetching secret from Key Vault for client: {}", clientId);
        try {
            return secretClient.getSecret("client-" + clientId).getValue();
        } catch (Exception ex) {
            log.warn("Key Vault secret retrieval failed for client: {} — {}", clientId, ex.getClass().getSimpleName());
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}
