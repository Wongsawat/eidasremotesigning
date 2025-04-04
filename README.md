# eIDAS Remote Signing Service

A Java Spring Boot application that implements an eIDAS-compliant remote signing service for XAdES and PAdES signatures. This service allows clients to remotely sign document digests that can be incorporated into advanced electronic signatures.

## Features

- OAuth2 authentication for secure API access
- Client registration API for automated onboarding
- Certificate management (create, list, update, delete)
- Remote signing of document digests for XAdES and PAdES
- eIDAS compliance checks for algorithms and key sizes
- Secure key storage with per-client isolation

## Technologies

- Java 17
- Spring Boot 3.4.4
- Spring Security with OAuth2 Authorization Server
- Spring Data JPA with H2 Database (can be replaced with any JDBC database)
- EU Digital Signature Services (DSS) library for eIDAS compliance
- Bouncy Castle for cryptographic operations
- Lombok for reducing boilerplate code

## Getting Started

### Prerequisites

- JDK 17 or higher
- Maven 3.6 or higher
- Git

### Building the Application

1. Clone the repository
   ```bash
   git clone https://github.com/your-organization/eidasremotesigning.git
   cd eidasremotesigning
   ```

2. Build the application
   ```bash
   mvn clean package
   ```

3. Run the application
   ```bash
   java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
   ```

The application will start on port 9000 by default.

### Configuration

The application can be configured using the `application.yml` file. Key configuration properties include:

- `server.port`: The HTTP port for the application (default: 9000)
- `app.keystore.base-path`: Directory for storing client keystores
- `app.keystore.directory-permissions`: POSIX permissions for keystore directories

## API Documentation

### Client Registration

```
POST /client-registration
Content-Type: application/json

{
  "clientName": "My Client",
  "scopes": ["signing"],
  "grantTypes": ["client_credentials"]
}
```

### Authentication

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {base64(client_id:client_secret)}

grant_type=client_credentials&scope=signing
```

### Certificate Management

```
POST /certificates
GET /certificates
GET /certificates/{certificateId}
PUT /certificates/{certificateId}
DELETE /certificates/{certificateId}
```

### Remote Signing

```
POST /api/v1/signing/digest
Content-Type: application/json
Authorization: Bearer {access_token}

{
  "certificateId": "cert-uuid",
  "digestValue": "base64-encoded-digest",
  "digestAlgorithm": "SHA-256",
  "signatureType": "XADES"
}
```

For detailed API documentation, see the [API Documentation](docs/API.md).

## Security Considerations

- In production, use a secure database instead of H2
- Configure proper SSL/TLS for HTTPS
- Store keystore passwords encrypted in the database
- Implement proper key ceremony procedures for production certificates
- Regular security audits and key rotation

## eIDAS Compliance

The service implements the following to ensure eIDAS compliance:

- Only allows secure hash algorithms (SHA-256, SHA-384, SHA-512)
- Enforces minimum RSA key size of 2048 bits
- Validates certificates before each signing operation
- Supports only eIDAS-compliant signature formats (XAdES, PAdES)
- Implements secure key storage with appropriate isolation

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [EU DSS Library](https://github.com/esig/dss) for eIDAS-compliant signing capabilities
- Spring Boot and Spring Security teams for their excellent frameworks
- Bouncy Castle for cryptographic implementations