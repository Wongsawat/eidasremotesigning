package com.wpanther.eidasremotesigning.repository;

import com.wpanther.eidasremotesigning.entity.TransactionAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface TransactionAuthorizationRepository extends JpaRepository<TransactionAuthorization, String> {
    
    /**
     * Find transaction by ID and client ID
     */
    Optional<TransactionAuthorization> findByIdAndClientId(String id, String clientId);
    
    /**
     * Find transaction by SAD token and client ID
     */
    Optional<TransactionAuthorization> findBySadAndClientId(String sad, String clientId);

    /**
     * Find all transactions for a client
     */
    List<TransactionAuthorization> findByClientId(String clientId);
    
    /**
     * Find all transactions for a certificate
     */
    List<TransactionAuthorization> findByCertificateId(String certificateId);
    
    /**
     * Find active transactions (not expired)
     */
    List<TransactionAuthorization> findByExpiresAtGreaterThan(Instant now);
    
    /**
     * Find transactions by status
     */
    List<TransactionAuthorization> findByStatus(String status);
    
    /**
     * Count active transactions for a client
     */
    long countByClientIdAndExpiresAtGreaterThan(String clientId, Instant now);
}