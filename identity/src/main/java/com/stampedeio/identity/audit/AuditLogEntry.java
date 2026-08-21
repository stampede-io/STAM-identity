package com.stampedeio.identity.audit;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_log")
public class AuditLogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private String payload;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "received_at", nullable = false, insertable = false)
    private Instant receivedAt;

    @Column(name = "kafka_offset")
    private Long kafkaOffset;

    @Column(name = "kafka_partition")
    private Integer kafkaPartition;

    protected AuditLogEntry() {}

    public AuditLogEntry(String eventType, String payload, Instant occurredAt,
                         Long kafkaOffset, Integer kafkaPartition) {
        this.eventType = eventType;
        this.payload = payload;
        this.occurredAt = occurredAt;
        this.kafkaOffset = kafkaOffset;
        this.kafkaPartition = kafkaPartition;
    }

    public UUID getId() { return id; }
    public String getEventType() { return eventType; }
    public String getPayload() { return payload; }
    public Instant getOccurredAt() { return occurredAt; }
    public Instant getReceivedAt() { return receivedAt; }
    public Long getKafkaOffset() { return kafkaOffset; }
    public Integer getKafkaPartition() { return kafkaPartition; }
}
