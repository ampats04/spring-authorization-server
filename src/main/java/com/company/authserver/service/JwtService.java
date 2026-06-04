package com.company.authserver.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    @Value("${app.jwt.expiry-seconds:900}")
    private long expirySeconds;

    public String generateToken(String clientId, String accountNumber) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(clientId)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirySeconds))
                .audience(List.of(audience))          // tip 8.1: always set aud
                .claim("client_id", clientId)
                // tip 8.5: account_number is in the payload; replace with an opaque
                // internal ref ID in production if this value is sensitive
                .claim("account_number", accountNumber)
                .id(UUID.randomUUID().toString())
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
