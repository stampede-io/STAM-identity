package com.stampedeio.identity.audit;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
@ConditionalOnBean(KafkaTemplate.class)
public class AuditLogConsumer {

    private static final Logger log = LoggerFactory.getLogger(AuditLogConsumer.class);

    private final AuditLogRepository repository;
    private final ObjectMapper objectMapper;

    public AuditLogConsumer(AuditLogRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @KafkaListener(topics = "identity.audit", groupId = "identity-audit-log")
    public void consume(ConsumerRecord<String, AuditEvent> record) {
        AuditEvent event = record.value();

        String payload;
        try {
            payload = objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize audit event {}", event.type(), e);
            return;
        }

        AuditLogEntry entry = new AuditLogEntry(
                event.type(),
                payload,
                event.occurredAt(),
                record.offset(),
                record.partition()
        );

        repository.save(entry);
        log.debug("Persisted audit event {} from partition {} offset {}",
                event.type(), record.partition(), record.offset());
    }
}
