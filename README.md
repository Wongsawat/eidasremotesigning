# eIDAS Remote Signing Service with PKCS#11 HSM Support

This service provides remote signing capabilities that comply with the eIDAS regulation, now with support for PKCS#11 Hardware Security Modules (HSMs).

## Key Features

- **PKCS#11 HSM Integration**: Support for hardware or software-based HSMs through the PKCS#11 interface
- **OAuth2 Authentication**: Client authentication using the OAuth2 client credentials flow
- **eIDAS Compliance**: Ensures all signatures meet eIDAS requirements
- **Certificate Management**: Register and manage certificates stored in HSMs
- **Remote Signing**: Sign document digests remotely using certificates in the HSM
- **Logging and Auditing**: Comprehensive logging for compliance and auditing purposes

## Architecture Changes

The application has been updated to support PKCS#11 HSMs with the following changes:

1. **PKCS#11 Provider Configuration**: Added configuration to load PKCS#11 providers (default is SoftHSM).

2. **Certificate Storage**: Certificates can now be stored in either:
   - PKCS#11 Hardware Security Modules (preferred)
   - Legacy PKCS#12 keystore files (for backward compatibility)

3. **PIN Management**: User PIN is now provided in the request header for HSM operations.

4. **Client Registration**: OAuth client registration is now separate from certificate association.

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven
- SoftHSM (for testing) or other PKCS#11-compatible HSM
- PKCS#11 library for your HSM

### Installation

1. Clone the repository
2. Build with Maven:
   ```
   mvn clean install
   ```

### Configuration

Configure your application.yml with your HSM details:

```yaml
app:
  pkcs11:
    provider: SunPKCS11
    name: SoftHSM
    library-path: /usr/lib/softhsm/libsofthsm2.so
    slot-list-index: 0
    use-config-file: false
```

For detailed instructions on setting up SoftHSM, refer to the [SoftHSM Setup Guide](SoftHSM-Setup-Guide.md).

## Usage

### 1. Register an OAuth2 Client

```bash
curl -X POST http://localhost:9000/client-registration \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "My Application",
    "scopes": ["signing"],
    "grantTypes": ["client_credentials"]
  }'
```

Response includes `clientId` and `clientSecret` that you'll need for authentication.

### 2. Get an OAuth2 Token

```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n client_id:client_secret | base64)" \
  -d "grant_type=client_credentials&scope=signing"
```

### 3. List Available Certificates in HSM

```bash
curl -X GET http://localhost:9000/certificates/pkcs11 \
  -H "Authorization: Bearer your_token" \
  -H "X-HSM-PIN: your_pin"
```

### 4. Associate a Certificate with Your Client

```bash
curl -X POST http://localhost:9000/certificates/pkcs11/associate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -H "X-HSM-PIN: your_pin" \
  -d '{
    "certificateAlias": "your-certificate-alias",
    "description": "My signing certificate"
  }'
```

### 5. Sign a Document Digest

```bash
curl -X POST http://localhost:9000/api/v1/signing/digest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -H "X-HSM-PIN: your_pin" \
  -d '{
    "certificateId": "your-certificate-id",
    "digestValue": "base64_encoded_digest",
    "digestAlgorithm": "SHA-256",
    "signatureType": "XADES"
  }'
```

## Security Considerations

1. **HSM PIN Protection**: The HSM PIN is transmitted in the HTTP header. In production, use HTTPS with mutual TLS authentication.

2. **PIN Policies**: Configure PIN policies on your HSM according to your security requirements.

3. **Certificate Access Control**: Only associated clients can access certificates, but the physical HSM should also implement access controls.

## Using Other HSMs

To use a different HSM, update the `library-path` in the configuration to point to your PKCS#11 library. You might also need to customize the PKCS#11 provider configuration based on your HSM's requirements.

## Running the Sample Client

A sample client is provided to demonstrate how to use the service with a PKCS#11 HSM:

```
java -cp target/eidasremotesigning-0.0.1-SNAPSHOT.jar com.wpanther.eidasremotesigning.client.PKCS11SampleClient
```

Make sure to update the client with your credentials and HSM PIN before running.
