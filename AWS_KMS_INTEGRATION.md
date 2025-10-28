# AWS KMS Integration Guide

This document explains how to use AWS KMS (Key Management Service) for secure key management in the eIDAS Remote Signing Service.

## Overview

AWS KMS integration allows you to use cloud-based Hardware Security Modules (HSMs) for cryptographic key management and signing operations. Unlike PKCS#11, AWS KMS keys **never leave the AWS infrastructure**, providing enhanced security.

## Key Features

✅ **Cloud-Based HSM** - Uses AWS CloudHSM infrastructure
✅ **Keys Never Exported** - Private keys remain in AWS
✅ **Automatic Key Rotation** - Built-in key management
✅ **IAM Integration** - Fine-grained access control
✅ **Audit Logging** - All operations logged in CloudTrail
✅ **Multi-Region Support** - Keys available across AWS regions

## Architecture

The system now supports **three storage modes**:

1. **PKCS#11** - Hardware Security Modules via PKCS#11 interface
2. **PKCS#12** - Software keystores (for development)
3. **AWSKMS** - AWS Key Management Service (new)

## Prerequisites

### 1. AWS Account Setup

You need an AWS account with KMS permissions. The following IAM permissions are required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Create an Asymmetric KMS Key

```bash
# Create an RSA key for signing
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --description "eIDAS Remote Signing Key" \
  --region us-east-1

# Or create an ECC key
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "eIDAS Remote Signing ECC Key" \
  --region us-east-1
```

Supported key specs:
- **RSA**: RSA_2048, RSA_3072, RSA_4096
- **ECC**: ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521

### 3. Generate a Certificate

Since AWS KMS only stores private keys, you need to generate a certificate that matches the KMS public key:

```bash
# Get the public key from KMS
aws kms get-public-key \
  --key-id YOUR_KEY_ID \
  --output text \
  --query PublicKey | base64 -d > public_key.der

# Convert to PEM format
openssl rsa -pubin -inform DER -in public_key.der -outform PEM -out public_key.pem

# Create a certificate signing request
openssl req -new -key private_key_placeholder.pem -out cert.csr \
  -subj "/C=BE/ST=Brussels/L=Brussels/O=YourOrg/CN=Signing Certificate"

# Get certificate from your CA, or create self-signed for testing
openssl x509 -req -days 365 -in cert.csr -signkey public_key.pem -out cert.pem

# Convert certificate to Base64 DER format
openssl x509 -in cert.pem -outform DER | base64 -w 0 > cert_base64.txt
```

**Note**: For production, you should obtain the certificate from a qualified Certificate Authority.

## Configuration

### Option 1: Using Environment Variables (Recommended)

```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
```

When running on EC2/ECS/Lambda, the application will automatically use the IAM role.

### Option 2: Using Explicit Credentials (Not Recommended for Production)

```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=false
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
```

### Option 3: Update application.yml

```yaml
app:
  aws:
    kms:
      enabled: true
      region: us-east-1
      use-default-credentials: true
```

## Usage

### 1. Start the Application

```bash
# Build the project
mvn clean package

# Run with AWS KMS enabled
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

### 2. Register an OAuth2 Client

```bash
curl -X POST http://localhost:9000/client-registration \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "KMS Test Client",
    "scopes": ["signing"],
    "grantTypes": ["client_credentials"]
  }'
```

Save the returned `client_id` and `client_secret`.

### 3. Get an Access Token

```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=client_credentials&scope=signing"
```

### 4. List Available KMS Keys

```bash
curl -X GET http://localhost:9000/api/v1/certificates/aws-kms/keys \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Associate a KMS Key with a Certificate

```bash
curl -X POST http://localhost:9000/api/v1/certificates/aws-kms/associate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "certificateBase64": "MIIDXTCCAkWgAwIBAgI...(base64 certificate)",
    "description": "Production Signing Certificate",
    "awsRegion": "us-east-1"
  }'
```

The response includes the `certificateId` (also called `credentialID` in CSC API).

### 6. Sign a Document using AWS KMS

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "clientId": "your_client_id",
    "credentialID": "certificate_id_from_step_5",
    "documentDigest": "base64_encoded_sha256_digest",
    "hashAlgo": "SHA-256",
    "signatureAttributes": {
      "signatureType": "XAdES"
    }
  }'
```

**Important**: For AWS KMS, you **do NOT need to provide a PIN**. Authentication is handled via AWS IAM.

### 7. Sign a Hash

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signHash \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "clientId": "your_client_id",
    "credentialID": "certificate_id_from_step_5",
    "hashAlgo": "SHA-256",
    "signatureData": {
      "hashToSign": ["base64_encoded_hash"]
    }
  }'
```

## Differences from PKCS#11

| Feature | PKCS#11 | AWS KMS |
|---------|---------|---------|
| **Key Location** | Local HSM | AWS Cloud |
| **PIN Required** | Yes | No (IAM authentication) |
| **Key Export** | Possible (depends on HSM) | Never |
| **Scaling** | Limited by hardware | Unlimited |
| **Cost** | Hardware + maintenance | Pay per operation |
| **Setup Complexity** | High | Medium |
| **Audit Trail** | HSM logs | CloudTrail |

## Security Considerations

### ✅ Best Practices

1. **Use IAM Roles**: When running on AWS infrastructure, always use IAM roles instead of access keys
2. **Enable CloudTrail**: Monitor all KMS operations
3. **Key Policies**: Restrict key usage to specific IAM principals
4. **Multi-Region Keys**: Consider using multi-region keys for disaster recovery
5. **Key Rotation**: Enable automatic key rotation for compliance

### ⚠️ Important Notes

- **Private keys never leave AWS KMS** - They cannot be exported or downloaded
- **Signing operations** are performed entirely within AWS infrastructure
- **Rate limits** apply - AWS KMS has default limits on API calls (e.g., 10,000 requests/second for Sign operation)
- **Costs** - AWS KMS charges per key per month + per API call

## Troubleshooting

### Error: "AWS KMS is not enabled or configured"

**Solution**: Set `app.aws.kms.enabled=true` in application.yml or environment variable `AWS_KMS_ENABLED=true`

### Error: "KMS key not found or not enabled"

**Solution**:
- Verify the key ID/ARN is correct
- Ensure the key usage is `SIGN_VERIFY`
- Check IAM permissions

### Error: "Access Denied"

**Solution**:
- Check IAM policy has required permissions
- Verify key policy allows the IAM principal
- Check AWS region matches configuration

### Error: "Certificate public key does not match KMS key"

**Solution**: The certificate must be generated using the public key from the KMS key. Use `aws kms get-public-key` to retrieve it.

## Cost Estimation

AWS KMS pricing (as of 2025):
- **Asymmetric keys**: $1.00 per month per key
- **Sign operation**: $0.15 per 10,000 requests
- **GetPublicKey**: $0.03 per 10,000 requests

**Example**:
- 1 key + 100,000 signatures/month = $1 + $1.50 = **$2.50/month**

## Migration from PKCS#11 to AWS KMS

1. **Generate new keys in AWS KMS** (cannot import existing keys for SIGN_VERIFY operations)
2. **Obtain new certificates** for the KMS public keys
3. **Associate KMS keys** using the API
4. **Update client configurations** to use new credential IDs
5. **Test signing operations** thoroughly
6. **Decommission old PKCS#11 certificates** once validated

## Additional Resources

- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [AWS KMS Pricing](https://aws.amazon.com/kms/pricing/)

## Support

For issues or questions:
- Check CloudTrail logs for KMS API errors
- Review IAM policies and key policies
- Enable debug logging: `logging.level.com.wpanther.eidasremotesigning.service.AWSKMSService=DEBUG`
