package com.company.authserver.store;

import com.company.authserver.properties.LocalClientProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Profile("!prod")
@RequiredArgsConstructor
public class InMemoryClientSecretStore implements ClientSecretStore {

    private final LocalClientProperties clientProperties;

    @Override
    public String getHashedSecret(String clientId) {
        log.debug("Looking up in-memory secret for client: {}", clientId);
        return clientProperties.getClients().stream()
                .filter(c -> c.getId().equals(clientId))
                .findFirst()
                .map(LocalClientProperties.ClientEntry::getSecret)
                .orElseThrow(() -> {
                    log.warn("Client not found in in-memory store: {}", clientId);
                    return new BadCredentialsException("Invalid credentials");
                });
    }
}
