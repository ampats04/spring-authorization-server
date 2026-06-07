package com.company.authserver.service;

import com.company.authserver.model.AuthAuditLog;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Stateless structured audit logger — no database required.
 * In production, pipe these structured log lines to a SIEM / log aggregator.
 */
@Slf4j
@Service
public class AuditLogger {

    public void log(AuthAuditLog audit) {
        log.info("AUTH_AUDIT_LOG={}", audit);
    }
}
