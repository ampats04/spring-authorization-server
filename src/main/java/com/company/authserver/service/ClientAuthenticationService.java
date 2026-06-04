package com.company.authserver.service;

import com.company.authserver.store.ClientSecretStore;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientAuthenticationService {

    private final ClientSecretStore secretStore;
    private final PasswordEncoder passwordEncoder;

    public void authenticate(String clientId, String clientSecret) {
        String stored = secretStore.getHashedSecret(clientId);
        if (!passwordEncoder.matches(clientSecret, stored)) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}
