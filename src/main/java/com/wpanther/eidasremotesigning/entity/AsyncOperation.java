package com.wpanther.eidasremotesigning.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Entity for storing asynchronous operation state
 * Used for tracking long-running operations in the CSC API
 */
@Entity
@Table(name = "async_operations")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AsyncOperation {

    @Id
    private String id;

    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @Column(name = "operation_type", nullable = false)
    private String operationType;
    
    @Column(name = "status", nullable = false)
    private String status;
    
    @Lob
    @Column(name = "result_data")
    private byte[] resultData;
    
    @Column(name = "error_message")
    private String errorMessage;
    
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    
    @Column(name = "updated_at")
    private Instant updatedAt;
    
    @Column(name = "expires_at")
    private Instant expiresAt;
    
    // Operation types: SIGNING, VERIFICATION, TIMESTAMP
    // States: CREATED, PROCESSING, COMPLETED, FAILED, EXPIRED
}