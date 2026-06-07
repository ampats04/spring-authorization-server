package com.company.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Generates a fresh 2048-bit RSA key pair at startup for JWT signing.
 *
 * Production note: replace the rsaKey() bean with one that loads the key
 * from Azure Key Vault (CryptographyClient) when running with the 'azure' profile.
 * The JWKS endpoint /.well-known/jwks.json will serve the matching public key.
 */
@Slf4j
@Configuration
@Profile("!prod")
public class JwtConfig {

    @Bean
    public RSAKey rsaKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        RSAKey key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("oauth2-signing-key-" + UUID.randomUUID())
                .build();

        log.info("Generated dummy RSA signing key — key ID: {}", key.getKeyID());
        return key;
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaKey) {
        // expose only the public portion via the JWKS endpoint
        return new JWKSet(rsaKey.toPublicJWK());
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey rsaKey) {
        ImmutableJWKSet<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }
}
