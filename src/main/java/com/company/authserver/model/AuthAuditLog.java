package com.company.authserver.model;

import java.time.Instant;

public record AuthAuditLog(
        String event,
        String clientId,
        String accountNumber,
        String jti,
        String correlationId,
        String sourceIp,
        String result,
        String failureReason,
        Instant timestamp
) {}
