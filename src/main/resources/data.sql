-- This file contains test data for development

-- Insert a test OAuth2 client
-- Note: In a real environment, you would use the client registration API
-- clientId: test-client, clientSecret: test-secret (hashed with BCrypt)
INSERT INTO oauth2_clients (id, client_id, client_secret, client_name, active, created_at)
VALUES ('1', 'test-client', '$2a$10$4XJ1d6u4MBBVtfoAgU4V3Ow3YJFouBYL1gE/JGzXfuTv5e2XAHNSi', 'Test Client', true, CURRENT_TIMESTAMP);

INSERT INTO oauth2_client_scopes (client_id, scope)
VALUES ('1', 'signing');

INSERT INTO oauth2_client_grant_types (client_id, grant_type)
VALUES ('1', 'client_credentials');

-- Note: We can't insert certificates because they require keystore files on disk
-- Use the API to create test certificates
