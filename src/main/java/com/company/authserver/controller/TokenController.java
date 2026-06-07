package com.company.authserver.controller;

import com.company.authserver.model.AuthAuditLog;
import com.company.authserver.model.TokenRequest;
import com.company.authserver.model.TokenResponse;
import com.company.authserver.service.AuditLogger;
import com.company.authserver.service.ClientAuthenticationService;
import com.company.authserver.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class TokenController {

    private final ClientAuthenticationService authService;
    private final JwtService jwtService;
    private final AuditLogger auditLogger;

    @PostMapping("/token")
    public ResponseEntity<TokenResponse> token(@RequestBody @Valid TokenRequest request,
                                               HttpServletRequest http) {
        String correlationId = UUID.randomUUID().toString();
        String sourceIp = resolveSourceIp(http);
        log.debug("Token request received — clientId: {}, correlationId: {}", request.clientId(), correlationId);

        try {
            authService.authenticate(request.clientId(), request.clientSecret());

            String token = jwtService.generateToken(request.clientId(), request.accountNumber());

            auditLogger.log(new AuthAuditLog(
                    "TOKEN_ISSUED",
                    request.clientId(),
                    request.accountNumber(),
                    "N/A",
                    correlationId,
                    sourceIp,
                    "SUCCESS",
                    null,
                    Instant.now()
            ));

            return ResponseEntity.ok(new TokenResponse(token, "Bearer", 900));

        } catch (BadCredentialsException ex) {
            auditLogger.log(new AuthAuditLog(
                    "TOKEN_FAILED",
                    request.clientId(),
                    request.accountNumber(),
                    null,
                    correlationId,
                    sourceIp,
                    "FAILED",
                    "INVALID_CREDENTIALS",   // tip 8.3: normalized reason, never raw ex.getMessage()
                    Instant.now()
            ));
            throw ex;

        } catch (Exception ex) {
            auditLogger.log(new AuthAuditLog(
                    "TOKEN_FAILED",
                    request.clientId(),
                    request.accountNumber(),
                    null,
                    correlationId,
                    sourceIp,
                    "FAILED",
                    "INTERNAL_ERROR",        // tip 8.3
                    Instant.now()
            ));
            throw ex;
        }
    }

    /**
     * tip 8.2: X-Forwarded-For should only be trusted after validating
     * that the request arrived through a known proxy. For simulation we
     * take the first value; harden this before going to production.
     */
    private String resolveSourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
