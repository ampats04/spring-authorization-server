package com.company.authserver.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Data
@Component
@Profile("local")
@ConfigurationProperties(prefix = "app")
public class LocalClientProperties {

    private List<ClientEntry> clients = new ArrayList<>();

    @Data
    public static class ClientEntry {
        private String id;
        private String secret;
    }
}
