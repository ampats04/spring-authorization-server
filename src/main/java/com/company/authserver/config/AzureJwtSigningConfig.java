package com.company.authserver.config;

import com.azure.security.keyvault.secrets.SecretClient;
import com.company.authserver.properties.AzureProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Configuration
@Profile("prod")
@RequiredArgsConstructor
public class AzureJwtSigningConfig {

    private final SecretClient secretClient;
    private final AzureProperties azure;

    @Bean
    public RSAKey rsaKey() throws Exception {
        log.info("Loading RSA signing key pair from Key Vault — private: {}, public: {}",
                azure.getSigningKeySecretName(), azure.getSigningPublicKeySecretName());

        RSAPrivateKey privateKey = parsePrivateKey(
                secretClient.getSecret(azure.getSigningKeySecretName()).getValue());
        RSAPublicKey publicKey = parsePublicKey(
                secretClient.getSecret(azure.getSigningPublicKeySecretName()).getValue());

        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        String kid = rsaKey.computeThumbprint().toString();
        log.info("RSA signing key loaded — kid (thumbprint): {}", kid);

        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).build();
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaKey) {
        return new JWKSet(rsaKey.toPublicJWK());
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey rsaKey) {
        ImmutableJWKSet<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    private RSAPrivateKey parsePrivateKey(String pem) throws Exception {
        String stripped = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(stripped);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private RSAPublicKey parsePublicKey(String pem) throws Exception {
        String stripped = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }
}
