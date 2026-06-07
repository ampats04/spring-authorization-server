package com.company.authserver.service;

import com.company.authserver.store.ClientSecretStore;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientAuthenticationService {

    private final ClientSecretStore secretStore;
    private final PasswordEncoder passwordEncoder;

    public void authenticate(String clientId, String clientSecret) {
        log.debug("Authenticating client: {}", clientId);
        String stored = secretStore.getHashedSecret(clientId);
        if (!passwordEncoder.matches(clientSecret, stored)) {
            log.warn("Authentication failed for client: {}", clientId);
            throw new BadCredentialsException("Invalid credentials");
        }
        log.debug("Client authenticated successfully: {}", clientId);
    }
}
