package com.company.authserver.controller;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Serves the public key in JWKS format.
 * The Spring Cloud Gateway resource server (or any downstream) points its
 * jwk-set-uri at this endpoint to validate JWT signatures without needing
 * access to the private key.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JWKSet jwkSet;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return jwkSet.toJSONObject();
    }
}
