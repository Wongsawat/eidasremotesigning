package com.wpanther.eidasremotesigning.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Entity for storing credential authorization transactions
 * Manages the state of signature authorization according to CSC API 2.0
 */
@Entity
@Table(name = "transaction_authorizations")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionAuthorization {

    @Id
    private String id;

    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @Column(name = "certificate_id", nullable = false)
    private String certificateId;
    
    @Column(name = "sad", nullable = false)
    private String sad;
    
    @Column(name = "num_signatures")
    private Integer numSignatures;
    
    @Column(name = "remaining_signatures")
    private Integer remainingSignatures;
    
    @Column(name = "description")
    private String description;
    
    @Column(name = "status", nullable = false)
    private String status;
    
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    
    @Column(name = "updated_at")
    private Instant updatedAt;
    
    // States: AUTHORIZATION_INITIALIZED, AUTHORIZED, EXPIRED, COMPLETED, FAILED
}