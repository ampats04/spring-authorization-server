package com.company.authserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    @Value("${app.jwt.expiry-seconds:3600}")
    private long expirySeconds;

    public String generateToken(String clientId, String accountNumber) {
        log.debug("Generating JWT for client: {}", clientId);
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(clientId)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expirySeconds))
                .audience(List.of(audience))
                .claim("client_id", clientId)
                .claim("account_number", accountNumber)
                .id(UUID.randomUUID().toString())
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
