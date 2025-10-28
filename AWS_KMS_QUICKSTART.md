# AWS KMS Quick Start Guide

## Enable AWS KMS in 5 Steps

### Step 1: Create a KMS Key

```bash
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --description "My Signing Key"
```

Save the `KeyId` from the response.

### Step 2: Configure the Application

```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
```

### Step 3: Start the Application

```bash
mvn clean package
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

### Step 4: Get an OAuth2 Token

```bash
# Register client
curl -X POST http://localhost:9000/client-registration \
  -H "Content-Type: application/json" \
  -d '{"clientName":"Test","scopes":["signing"],"grantTypes":["client_credentials"]}'

# Get token (replace client_id:client_secret)
curl -X POST http://localhost:9000/oauth2/token \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=client_credentials&scope=signing"
```

### Step 5: Associate Your KMS Key

```bash
curl -X POST http://localhost:9000/api/v1/certificates/aws-kms/associate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kmsKeyId": "YOUR_KEY_ID",
    "certificateBase64": "YOUR_BASE64_CERT",
    "description": "My Signing Cert"
  }'
```

## Sign a Document

```bash
curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "your_client_id",
    "credentialID": "cert_id_from_step5",
    "documentDigest": "BASE64_SHA256_DIGEST",
    "hashAlgo": "SHA-256"
  }'
```

## Key Differences from PKCS#11

- ❌ **No PIN required** - Uses AWS IAM authentication
- ✅ **Keys never leave AWS** - Enhanced security
- ✅ **Unlimited scaling** - No hardware limits
- 💰 **Pay-per-use** - ~$2.50/month for 100k signatures

For detailed documentation, see [AWS_KMS_INTEGRATION.md](AWS_KMS_INTEGRATION.md)
