package com.company.authserver.store;

import com.company.authserver.properties.LocalClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

@Component
@Profile("local")
@RequiredArgsConstructor
public class InMemoryClientSecretStore implements ClientSecretStore {

    private final LocalClientProperties clientProperties;

    @Override
    public String getHashedSecret(String clientId) {
        return clientProperties.getClients().stream()
                .filter(c -> c.getId().equals(clientId))
                .findFirst()
                .map(LocalClientProperties.ClientEntry::getSecret)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
    }
}
