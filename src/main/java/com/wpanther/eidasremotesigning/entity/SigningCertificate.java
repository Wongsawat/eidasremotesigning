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

    // Path to the PKCS12 keystore file in the filesystem
    @Column(nullable = false)
    private String keystorePath;
    
    // Password used to protect the keystore (should be encrypted in production)
    @Column(nullable = false)
    private String keystorePassword;

    // Certificate alias in the keystore (typically the serial number)
    @Column(nullable = false)
    private String keystoreAlias;

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