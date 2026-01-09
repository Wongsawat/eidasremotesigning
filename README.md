# eIDAS Remote Signing Service

A Spring Boot application that provides eIDAS-compliant remote signing capabilities with support for **PKCS#11 hardware tokens** and **AWS KMS**.

## Overview

This service allows for secure digital signing operations compliant with the eIDAS (Electronic Identification, Authentication and Trust Services) regulation. It implements the Cloud Signature Consortium (CSC) API v2.0 for standardized remote signing operations.

Key features:
- OAuth2 client registration and authentication
- **Multiple key storage options**: PKCS#11 HSM, AWS KMS, PKCS#12
- XAdES and PAdES signature formats
- Comprehensive audit logging and metrics
- Integration with Hardware Security Modules (HSM) and AWS KMS
- Complete CSC API v2.0 implementation
- **Asynchronous signing operations for large documents and batch processing**
- Transaction-based authorization for secure signing
- Timestamp generation and validation
- **Cloud-native with AWS KMS support** ☁️

## Storage Options

| Storage Type | Security | Production Ready | Use Case |
|--------------|----------|------------------|----------|
| **AWS KMS** ☁️ | ⭐⭐⭐⭐⭐ | ✅ Yes | Cloud-native, scalable production |
| **PKCS#11 HSM** | ⭐⭐⭐⭐⭐ | ✅ Yes | On-premise production with hardware HSM |
| **PKCS#12** | ⭐⭐ | ⚠️ Testing only | Development and testing |

## System Requirements

- Java 17 or higher
- Maven 3.6+
- A compatible database (H2 is included for development)
- **Optional**: SoftHSM or other PKCS#11 compliant HSM
- **Optional**: AWS account with KMS access

## Quick Start

Choose your key management approach:

### Option A: AWS KMS (Recommended for Cloud Deployment) ☁️

**5-Minute Setup:**

```bash
# 1. Create KMS key
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_2048

# 2. Configure application
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1

# 3. Build and run
mvn clean package
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

📘 **[Complete AWS KMS Setup Guide →](AWS_KMS_SETUP_GUIDE.md)**
📋 **[Quick Reference →](AWS_KMS_QUICK_REFERENCE.md)**

### Option B: PKCS#11 Hardware HSM (For On-Premise Deployment)

### 1. Configure PKCS#11 Provider

Ensure you have a PKCS#11 provider correctly configured. The default configuration uses SoftHSM. Update the PKCS#11 configuration in `application.yml` for your environment.

```yaml
app:
  pkcs11:
    provider: SunPKCS11
    name: SoftHSM
    library-path: /usr/lib/softhsm/libsofthsm2.so
    slot-list-index: 0
    use-config-file: true
    config-file: /path/to/pkcs11.cfg
  tsp:
    url: https://freetsa.org/tsr  # Timestamp service URL (HTTPS, free, RFC 3161 compliant)
```

### 2. Build the Application

```bash
mvn clean package
```

### 3. Run the Application

```bash
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

The service will start on port 9000 by default.

### 4. Register a Client

```bash
curl -X POST http://localhost:9000/client-registration \
     -H "Content-Type: application/json" \
     -d '{"clientName":"Test Client","scopes":["signing"],"grantTypes":["client_credentials"]}'
```

### 5. Obtain an OAuth2 Token

```bash
curl -X POST http://localhost:9000/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic $(echo -n client_id:client_secret | base64)" \
     -d "grant_type=client_credentials&scope=signing"
```

## API Documentation

### CSC API v2.0 Endpoints

The service implements the following CSC API v2.0 endpoints:

#### Information and Service Discovery
| Endpoint | Purpose |
|----------|---------|
| GET /csc/v2/info | Get service information |

#### Credential Management
| Endpoint | Purpose |
|----------|---------|
| POST /csc/v2/credentials/list | List available certificates |
| POST /csc/v2/credentials/info | Get certificate details |
| POST /csc/v2/credentials/associate | Associate a certificate |
| POST /csc/v2/credentials/authorize | Authorize a credential for signing |
| POST /csc/v2/credentials/authorizeStatus | Check authorization status |
| POST /csc/v2/credentials/extendTransaction | Extend authorization validity |

#### Signing Operations
| Endpoint | Purpose |
|----------|---------|
| POST /csc/v2/signatures/signHash | Sign a hash value (sync/async) |
| POST /csc/v2/signatures/signDocument | Sign a complete document (sync/async) |
| POST /csc/v2/signatures/status | Check status of asynchronous operations |
| POST /csc/v2/signatures/timestamp | Create a timestamp for a document or hash |

#### OAuth2 Endpoints
| Endpoint | Purpose |
|----------|---------|
| GET /csc/v2/oauth2/authorize | OAuth2 authorization endpoint |
| POST /csc/v2/oauth2/token | OAuth2 token endpoint |

### Example: List Credentials

```bash
curl -X POST http://localhost:9000/csc/v2/credentials/list \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{"clientId":"your_client_id","credentials":{"pin":{"value":"1234"}}}'
```

### Example: Authorize a Credential

```bash
curl -X POST http://localhost:9000/csc/v2/credentials/authorize \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "credentialID": "your_certificate_id",
           "credentials": {
             "pin": {
               "value": "1234"
             }
           },
           "numSignatures": "1",
           "validityPeriod": 900,
           "description": "Signing invoice #123"
         }'
```

### Example: Sign a Hash

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signHash \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "credentialID": "your_certificate_id",
           "hashAlgo": "SHA-256",
           "credentials": {
             "pin": {
               "value": "1234"
             }
           },
           "signatureData": {
             "hashToSign": ["base64_encoded_hash"],
             "signatureAttributes": {
               "signatureType": "XAdES"
             }
           }
         }'
```

### Example: Sign a Document

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "credentialID": "your_certificate_id",
           "documentID": "doc-123",
           "document": "base64_encoded_document",
           "hashAlgo": "SHA-256",
           "credentials": {
             "pin": {
               "value": "1234"
             }
           },
           "signatureAttributes": {
             "signatureType": "PAdES"
           },
           "signatureOptions": {
             "serverTimestamp": "true"
           }
         }'
```

### Example: Asynchronous Document Signing

For large documents or batch operations, use async signing to avoid timeouts:

**Step 1: Submit async signing request**

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "credentialID": "your_certificate_id",
           "document": "base64_encoded_large_document",
           "hashAlgo": "SHA-256",
           "async": true,
           "credentials": {
             "pin": {
               "value": "1234"
             }
           },
           "signatureAttributes": {
             "signatureType": "PAdES"
           }
         }'
```

**Response (immediate):**
```json
{
  "operationID": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Step 2: Poll for operation status**

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/status \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "transactionID": "550e8400-e29b-41d4-a716-446655440000"
         }'
```

**Response (while processing):**
```json
{
  "status": "PROCESSING"
}
```

**Response (when complete):**
```json
{
  "status": "COMPLETED",
  "signedDocument": "base64_encoded_signed_document",
  "signedDocumentDigest": "base64_digest",
  "signatureAlgorithm": "SHA256withRSA",
  "certificate": "base64_certificate",
  "timestampData": {
    "timestamp": "...",
    "timestampGenerationTime": 1609459200000
  }
}
```

**Possible Status Values:**
- `PROCESSING` - Operation in progress
- `COMPLETED` - Successfully signed
- `FAILED` - Operation failed (check `errorMessage` field)
- `EXPIRED` - Operation timed out

### Example: Create a Timestamp

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/timestamp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{
           "clientId": "your_client_id",
           "documentDigest": "base64_encoded_digest",
           "hashAlgo": "SHA-256"
         }'
```

## Metrics and Logging

The service provides comprehensive metrics about signing operations:

```bash
curl -X GET http://localhost:9000/api/v1/metrics \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

For audit purposes, you can retrieve logs of signing operations:

```bash
curl -X GET http://localhost:9000/api/v1/logs \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Sample Client

The project includes a sample Java client (`CSCSampleClient.java`) that demonstrates how to use the API.

To run the sample client:

```bash
mvn exec:java -Dexec.mainClass="com.wpanther.eidasremotesigning.client.CSCSampleClient"
```

## Architecture

The application is built on Spring Boot and follows a standard layered architecture:

- **Controller Layer**: Handles HTTP requests and responses
- **Service Layer**: Contains business logic
- **Repository Layer**: Manages data access
- **Entity Layer**: Domain objects representing database entities
- **DTO Layer**: Data transfer objects for API communication

### Key Components

- **OAuth2 Authorization Server**: Provides authentication and authorization
- **PKCS#11 Integration**: Enables hardware token access
- **Signing Service**: Handles digital signature operations
- **CSC API Implementation**: Implements the CSC API v2.0 specification
- **Transaction Management**: Handles secure authorization for signing operations
- **Audit Logging**: Records all signing operations for compliance
- **Metrics Service**: Provides usage statistics

## Transaction-Based Authorization

The service implements a transaction-based authorization model for secure signing:

1. Client authorizes a credential for signing (`/csc/v2/credentials/authorize`)
2. Service returns a Signature Activation Data (SAD) token
3. Client uses the SAD token in signing operations
4. Transaction enforces constraints (number of signatures, validity period)

This follows the CSC API v2.0 specification for secure remote signing.

## Configuration Options

The application can be configured through the `application.yml` file. Key configuration areas include:

- Server port and context path
- Database connection details
- OAuth2 server settings
- PKCS#11 provider settings
- AWS KMS settings
- Keystore base path
- Timestamp service URL
- **Async operation thread pool and lifecycle settings**
- Logging levels

## Security Considerations

- The service requires proper HSM initialization and security
- Client secrets should be properly secured
- Production deployments should use TLS/HTTPS
- Consider using a firewall to restrict access to the API
- Configure appropriate token lifetimes and scope restrictions
- Use transaction-based authorization for enhanced security

## Compliance

This service is designed to be compliant with:

- eIDAS Regulation (EU) 910/2014
- Cloud Signature Consortium API v2.0
- ETSI standards for Advanced Electronic Signatures (XAdES, PAdES)

## Advanced Usage

### Using with a Real HSM

For production environments, configure the PKCS#11 provider to connect to your HSM:

1. Install the HSM vendor's PKCS#11 library
2. Update the `app.pkcs11.library-path` property to point to your HSM's library
3. Configure any HSM-specific settings (slot ID, etc.)
4. Restart the application

### Customizing Signature Parameters

The service supports customized signature parameters through the signature attributes in the signing request. This allows for specifying additional signature attributes required for specific use cases.

### Asynchronous Signing

The service provides full asynchronous signing support for high-throughput environments and large documents.

**When to Use Async Signing:**
- Large PDF documents (>10MB)
- Batch signing multiple documents
- Mobile clients with unstable connections
- High-latency environments
- Avoiding HTTP timeout issues

**Async Signing Workflow:**

1. **Submit Request**: Add `"async": true` to any signing request
2. **Receive Operation ID**: Server returns immediately with `operationID`
3. **Background Processing**: Signing occurs in thread pool
4. **Poll Status**: Use `/csc/v2/signatures/status` with the `operationID`
5. **Retrieve Results**: Full signature data returned when `status: COMPLETED`

**Operation Lifecycle:**
- Operations expire after 30 minutes (configurable)
- Completed operations retained for 7 days
- Automatic cleanup removes expired and old operations

**Configuration** (in `application.yml`):
```yaml
app:
  async:
    core-pool-size: 5                # Minimum worker threads
    max-pool-size: 10                # Maximum worker threads
    queue-capacity: 100              # Queue size before rejection
    thread-name-prefix: "async-signing-"
    operation-expiry-minutes: 30     # Operation timeout
    cleanup-cron: "0 0 * * * *"      # Hourly expired cleanup
    deletion-cron: "0 0 2 * * *"     # Daily old operation deletion
    retention-days: 7                # Keep completed ops for 7 days
```

**Performance Tuning:**
- `core-pool-size`: Set to average concurrent signing operations
- `max-pool-size`: Set to peak concurrent operations
- `queue-capacity`: Buffer for traffic spikes
- `operation-expiry-minutes`: Match client timeout expectations

**Polling Best Practices:**
- Use exponential backoff: 1s, 2s, 4s, 8s intervals
- Stop polling after operation expires (default 30 minutes)
- Cache completed results client-side

### Timestamping

The service supports timestamping according to RFC 3161:

1. Submit a document or digest for timestamping
2. Receive a timestamp token from a trusted timestamp authority
3. Timestamp tokens can be included in signatures for long-term validity

## Troubleshooting

### Common Issues

1. **PKCS#11 Connection Errors**:
   - Verify the library path is correct
   - Ensure the HSM is properly initialized
   - Check that the slot ID is correct

2. **Authentication Failures**:
   - Verify client ID and secret
   - Ensure the token has not expired
   - Check requested scopes match client registration

3. **Signing Errors**:
   - Verify the PIN is correct
   - Ensure the certificate is active
   - Check that the digest algorithm is supported
   - Verify transaction authorization status

4. **Timestamp Errors**:
   - Check timestamp service URL is accessible
   - Verify proper network connectivity
   - Ensure digest algorithm is supported by the TSA

5. **Async Operation Issues**:
   - **Operation Not Found**: Check `operationID` is correct and hasn't expired
   - **Status Stuck on PROCESSING**: Check thread pool is not saturated (increase `max-pool-size`)
   - **Operations Timing Out**: Increase `operation-expiry-minutes` for large documents
   - **Queue Rejection**: Increase `queue-capacity` or reduce submission rate
   - **Check thread pool metrics**: Monitor `asyncSigningExecutor` thread pool stats

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

For questions or support, please contact [rabbit_roger[แอท]yahoo[ดอท]com].
