-- OAuth2 client tables
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret VARCHAR(1000) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth2_client_scopes (
    client_id VARCHAR(255) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    PRIMARY KEY (client_id, scope),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id)
);

CREATE TABLE IF NOT EXISTS oauth2_client_grant_types (
    client_id VARCHAR(255) NOT NULL,
    grant_type VARCHAR(255) NOT NULL,
    PRIMARY KEY (client_id, grant_type),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(id)
);

-- Signing certificates table
CREATE TABLE IF NOT EXISTS signing_certificates (
    id VARCHAR(255) PRIMARY KEY,
    description VARCHAR(255),
    keystore_path VARCHAR(500) NOT NULL,
    keystore_password VARCHAR(255) NOT NULL,
    keystore_alias VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    CONSTRAINT fk_certificate_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id)
);

-- Signing logs table
CREATE TABLE IF NOT EXISTS signing_logs (
    id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    certificate_id VARCHAR(255) NOT NULL,
    request_ip VARCHAR(45),  -- To accommodate IPv6 addresses
    signature_algorithm VARCHAR(100) NOT NULL,
    digest_algorithm VARCHAR(50) NOT NULL,
    signature_type VARCHAR(20) NOT NULL,
    digest_value TEXT,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_log_certificate FOREIGN KEY (certificate_id) REFERENCES signing_certificates(id)
);

-- Performance optimization indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id ON oauth2_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_certificates_client_id ON signing_certificates(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_client_id ON signing_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_certificate_id ON signing_logs(certificate_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_created_at ON signing_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_signing_logs_status ON signing_logs(status);
CREATE INDEX IF NOT EXISTS idx_signing_logs_signature_type ON signing_logs(signature_type);