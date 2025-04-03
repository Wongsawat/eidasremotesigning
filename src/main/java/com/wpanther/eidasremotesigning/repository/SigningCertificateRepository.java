package com.wpanther.eidasremotesigning.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.wpanther.eidasremotesigning.entity.SigningCertificate;

@Repository
public interface SigningCertificateRepository extends JpaRepository<SigningCertificate, String> {
    /**
     * Find all certificates belonging to a specific OAuth2 client ID
     */
    List<SigningCertificate> findByClientId(String clientId);
    
    /**
     * Find a specific certificate by ID that belongs to a specific OAuth2 client ID
     */
    Optional<SigningCertificate> findByIdAndClientId(String id, String clientId);
    
    /**
     * Count certificates by client ID
     */
    long countByClientId(String clientId);
    
    /**
     * Find all active certificates for a client
     */
    List<SigningCertificate> findByClientIdAndActiveTrue(String clientId);
}