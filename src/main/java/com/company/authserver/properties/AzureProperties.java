package com.company.authserver.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Data
@Component
@Profile("azure")
@ConfigurationProperties(prefix = "app.azure")
public class AzureProperties {

    private String vaultUrl;
    private String clientId;
    private String clientSecret;
    private String tenantId;
    private String signingKeyId;
}
