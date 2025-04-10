package com.wpanther.eidasremotesigning.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "signing_certificates")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningCertificate {

    @Id
    private String id;

    // Basic description for the certificate
    @Column(length = 255)
    private String description;

    // Storage type - PKCS11 or PKCS12 (for backward compatibility)
    @Column(nullable = false)
    private String storageType;
    
    // Certificate alias (label) in the PKCS#11 token
    @Column(nullable = false)
    private String certificateAlias;

    // Path to keystore file - only used if storageType is PKCS12
    @Column
    private String keystorePath;
    
    // Password for keystore - only used if storageType is PKCS12
    @Column
    private String keystorePassword;

    // Provider name for PKCS#11 (e.g., "SunPKCS11-SoftHSM")
    @Column
    private String providerName;
    
    // Slot ID for PKCS#11
    @Column
    private Integer slotId;

    @Column(nullable = false)
    private boolean active;

    // Reference to the client that owns this certificate - properly linked to OAuth2Client
    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", referencedColumnName = "client_id", insertable = false, updatable = false)
    private OAuth2Client client;

    @Column(nullable = false)
    private Instant createdAt;

    @Column
    private Instant updatedAt;
}
