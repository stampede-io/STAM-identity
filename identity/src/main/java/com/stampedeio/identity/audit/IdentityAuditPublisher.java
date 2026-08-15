package com.stampedeio.identity.audit;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnBean(KafkaTemplate.class)
public class IdentityAuditPublisher {

    private static final Logger log = LoggerFactory.getLogger(IdentityAuditPublisher.class);
    private static final String TOPIC = "identity.audit";

    private final KafkaTemplate<String, AuditEvent> kafkaTemplate;

    public IdentityAuditPublisher(KafkaTemplate<String, AuditEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publish(AuditEvent event) {
        String key = resolveKey(event);
        kafkaTemplate.send(TOPIC, key, event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish audit event {} with key {}", event.type(), key, ex);
                    } else {
                        log.debug("Published audit event {} to partition {} offset {}",
                                event.type(),
                                result.getRecordMetadata().partition(),
                                result.getRecordMetadata().offset());
                    }
                });
    }

    private String resolveKey(AuditEvent event) {
        return switch (event) {
            case AuditEvent.UserLoggedIn e -> e.userId().toString();
            case AuditEvent.LoginFailed e -> e.email();
            case AuditEvent.TokenRefreshed e -> e.userId().toString();
            case AuditEvent.RefreshTokenReuseDetected e -> e.email();
            case AuditEvent.RoleChanged e -> e.targetUserId().toString();
        };
    }
}
