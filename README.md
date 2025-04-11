# eIDAS Remote Signing Service

A Spring Boot application that provides eIDAS-compliant remote signing capabilities using PKCS#11 hardware tokens.

## Overview

This service allows for secure digital signing operations compliant with the eIDAS (Electronic Identification, Authentication and Trust Services) regulation. It implements the Cloud Signature Consortium (CSC) API v2.0 for standardized remote signing operations.

Key features:
- OAuth2 client registration and authentication
- Certificate management for PKCS#11 hardware tokens
- XAdES and PAdES signature formats
- Comprehensive audit logging
- Integration with Hardware Security Modules (HSM)
- Complete CSC API v2.0 implementation

## System Requirements

- Java 17 or higher
- SoftHSM or other PKCS#11 compliant HSM
- Maven 3.6+
- A compatible database (H2 is included for development)

## Quick Start

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

| Endpoint | Purpose |
|----------|---------|
| GET /csc/v2/info | Get service information |
| POST /csc/v2/credentials/list | List available certificates |
| POST /csc/v2/credentials/info | Get certificate details |
| POST /csc/v2/credentials/associate | Associate a certificate |
| POST /csc/v2/signatures/signHash | Sign a hash value |

### Example: List Credentials

```bash
curl -X POST http://localhost:9000/csc/v2/credentials/list \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{"clientId":"your_client_id","credentials":{"pin":{"value":"1234"}}}'
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
- **Audit Logging**: Records all signing operations for compliance
- **Metrics Service**: Provides usage statistics

## Configuration Options

The application can be configured through the `application.yml` file. Key configuration areas include:

- Server port and context path
- Database connection details
- OAuth2 server settings
- PKCS#11 provider settings
- Keystore base path
- Logging levels

## Security Considerations

- The service requires proper HSM initialization and security
- Client secrets should be properly secured
- Production deployments should use TLS/HTTPS
- Consider using a firewall to restrict access to the API
- Configure appropriate token lifetimes and scope restrictions

## Compliance

This service is designed to be compliant with:

- eIDAS Regulation (EU) 910/2014
- Cloud Signature Consortium API v2.0
- ETSI standards for Advanced Electronic Signatures

## Advanced Usage

### Using with a Real HSM

For production environments, configure the PKCS#11 provider to connect to your HSM:

1. Install the HSM vendor's PKCS#11 library
2. Update the `app.pkcs11.library-path` property to point to your HSM's library
3. Configure any HSM-specific settings (slot ID, etc.)
4. Restart the application

### Customizing Signature Parameters

The service supports customized signature parameters through the `signatureParams` field in the signing request. This allows for specifying additional signature attributes required for specific use cases.

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

For questions or support, please contact [rabbit_roger[แอท]yahoo[ดอท]com].