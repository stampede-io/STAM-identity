package com.stampedeio.identity.config;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * STAM-67 / CLAUDE.md §4.6: normalizes the gateway-forwarded X-Correlation-Id
 * header into a valid UUID. Mirrors STAM-booking's CorrelationIds.
 */
public final class CorrelationIds {

    private static final Logger log = LoggerFactory.getLogger(CorrelationIds.class);

    private CorrelationIds() {
    }

    public static UUID parseOrNew(String raw) {
        if (raw == null || raw.isBlank()) {
            return UUID.randomUUID();
        }
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException e) {
            log.warn("Discarding malformed correlation id: {}", raw);
            return UUID.randomUUID();
        }
    }
}
