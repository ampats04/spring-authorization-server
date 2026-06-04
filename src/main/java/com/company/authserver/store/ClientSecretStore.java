package com.company.authserver.store;

/**
 * Abstraction over where client secrets are stored.
 *
 * Local profile: in-memory map from application.yml.
 * Azure profile: Azure Key Vault Secrets.
 */
public interface ClientSecretStore {

    /**
     * Returns the encoded/hashed secret for the given clientId.
     * Throws BadCredentialsException if the client does not exist.
     */
    String getHashedSecret(String clientId);
}
