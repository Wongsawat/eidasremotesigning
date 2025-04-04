package com.wpanther.eidasremotesigning.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Entity for storing signing operation logs
 * Provides an audit trail for compliance purposes
 */
@Entity
@Table(name = "signing_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningLog {

    @Id
    private String id;

    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @Column(name = "certificate_id", nullable = false)
    private String certificateId;
    
    @Column(name = "request_ip")
    private String requestIp;
    
    @Column(name = "signature_algorithm", nullable = false)
    private String signatureAlgorithm;
    
    @Column(name = "digest_algorithm", nullable = false)
    private String digestAlgorithm;
    
    @Column(name = "signature_type", nullable = false)
    private String signatureType;
    
    // We store the digest value (NOT the document itself)
    // for audit purposes while maintaining confidentiality
    @Column(name = "digest_value")
    private String digestValue;
    
    // We do NOT store the actual signature for security reasons
    // Just log that it happened
    
    @Column(name = "status", nullable = false)
    private String status;  // SUCCESS, FAILED
    
    @Column(name = "error_message")
    private String errorMessage;
    
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}