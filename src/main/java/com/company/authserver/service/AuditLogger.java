package com.company.authserver.service;

import com.company.authserver.model.AuthAuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Stateless structured audit logger — no database required.
 * In production, pipe these structured log lines to a SIEM / log aggregator.
 */
@Service
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    public void log(AuthAuditLog audit) {
        log.info("AUTH_AUDIT_LOG={}", audit);
    }
}
