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