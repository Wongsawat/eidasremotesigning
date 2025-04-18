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

-- Updated signing certificates table with PKCS#11 support
CREATE TABLE IF NOT EXISTS signing_certificates (
    id VARCHAR(255) PRIMARY KEY,
    description VARCHAR(255),
    storage_type VARCHAR(10) NOT NULL, -- PKCS11 or PKCS12
    certificate_alias VARCHAR(255) NOT NULL,
    keystore_path VARCHAR(500),
    keystore_password VARCHAR(255),
    provider_name VARCHAR(255),
    slot_id INTEGER,
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

-- Transaction authorization table for CSC API 2.0
CREATE TABLE IF NOT EXISTS transaction_authorizations (
    id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    certificate_id VARCHAR(255) NOT NULL,
    sad VARCHAR(255) NOT NULL,
    num_signatures INTEGER,
    remaining_signatures INTEGER,
    description VARCHAR(500),
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    CONSTRAINT fk_transaction_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id),
    CONSTRAINT fk_transaction_certificate FOREIGN KEY (certificate_id) REFERENCES signing_certificates(id)
);

-- CSC API asynchronous operations table
CREATE TABLE IF NOT EXISTS async_operations (
    id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    result_data BYTEA,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    expires_at TIMESTAMP,
    CONSTRAINT fk_async_operation_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id)
);

-- Performance optimization indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id ON oauth2_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_certificates_client_id ON signing_certificates(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_client_id ON signing_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_certificate_id ON signing_logs(certificate_id);
CREATE INDEX IF NOT EXISTS idx_signing_logs_created_at ON signing_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_signing_logs_status ON signing_logs(status);
CREATE INDEX IF NOT EXISTS idx_signing_logs_signature_type ON signing_logs(signature_type);
CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_client_id ON transaction_authorizations(client_id);
CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_certificate_id ON transaction_authorizations(certificate_id);
CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_status ON transaction_authorizations(status);
CREATE INDEX IF NOT EXISTS idx_transaction_authorizations_expires_at ON transaction_authorizations(expires_at);
CREATE INDEX IF NOT EXISTS idx_async_operations_client_id ON async_operations(client_id);
CREATE INDEX IF NOT EXISTS idx_async_operations_status ON async_operations(status);
CREATE INDEX IF NOT EXISTS idx_async_operations_operation_type ON async_operations(operation_type);