package com.company.authserver.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@Component
@Profile("!prod")
@ConfigurationProperties(prefix = "app")
public class LocalClientProperties {

    @Valid
    @NotEmpty(message = "At least one client entry must be configured under app.clients")
    private List<ClientEntry> clients = new ArrayList<>();

    @Data
    public static class ClientEntry {

        @NotBlank(message = "Client id must not be blank")
        private String id;

        @NotBlank(message = "Client secret must not be blank")
        private String secret;
    }
}
