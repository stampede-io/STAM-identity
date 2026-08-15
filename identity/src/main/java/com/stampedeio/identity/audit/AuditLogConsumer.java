package com.stampedeio.identity.audit;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Component
public class AuditLogConsumer {

    private static final Logger log = LoggerFactory.getLogger(AuditLogConsumer.class);

    private final AuditLogRepository repository;
    private final JsonMapper jsonMapper;

    public AuditLogConsumer(AuditLogRepository repository, JsonMapper jsonMapper) {
        this.repository = repository;
        this.jsonMapper = jsonMapper;
    }

    @KafkaListener(topics = "identity.audit", groupId = "identity-audit-log")
    public void consume(ConsumerRecord<String, AuditEvent> record) {
        AuditEvent event = record.value();

        String payload;
        try {
            payload = jsonMapper.writeValueAsString(event);
        } catch (JacksonException e) {
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
