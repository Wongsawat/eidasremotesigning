package com.wpanther.eidasremotesigning.repository;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.wpanther.eidasremotesigning.entity.SigningLog;

@Repository
public interface SigningLogRepository extends JpaRepository<SigningLog, String> {
    
    /**
     * Find all signing logs for a specific client
     */
    List<SigningLog> findByClientId(String clientId);
    
    /**
     * Find all signing logs for a specific certificate
     */
    List<SigningLog> findByCertificateId(String certificateId);
    
    /**
     * Find logs within a date range
     */
    List<SigningLog> findByCreatedAtBetween(Instant start, Instant end);
    
    /**
     * Find logs by client and date range
     */
    List<SigningLog> findByClientIdAndCreatedAtBetween(String clientId, Instant start, Instant end);
    
    /**
     * Count successful and failed operations
     */
    long countByStatus(String status);
    
    /**
     * Count operations by client and status
     */
    long countByClientIdAndStatus(String clientId, String status);
    
    /**
     * Get signing activity summary by signature type
     */
    @Query("SELECT l.signatureType, COUNT(l) FROM SigningLog l WHERE l.status = 'SUCCESS' GROUP BY l.signatureType")
    List<Object[]> countBySignatureType();
}