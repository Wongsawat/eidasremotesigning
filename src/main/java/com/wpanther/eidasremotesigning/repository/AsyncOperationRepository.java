package com.wpanther.eidasremotesigning.repository;

import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface AsyncOperationRepository extends JpaRepository<AsyncOperation, String> {
    
    /**
     * Find operation by ID and client ID
     */
    Optional<AsyncOperation> findByIdAndClientId(String id, String clientId);
    
    /**
     * Find all operations for a client
     */
    List<AsyncOperation> findByClientId(String clientId);
    
    /**
     * Find operations by type and status
     */
    List<AsyncOperation> findByOperationTypeAndStatus(String operationType, String status);
    
    /**
     * Find operations that have expired
     */
    List<AsyncOperation> findByExpiresAtLessThan(Instant now);
    
    /**
     * Count active operations for a client
     */
    long countByClientIdAndStatusNot(String clientId, String status);
}