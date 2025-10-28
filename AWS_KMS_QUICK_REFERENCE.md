# AWS KMS Quick Reference Card

## 🚀 Quick Setup (5 Commands)

```bash
# 1. Create KMS signing key
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_2048

# 2. Get public key
aws kms get-public-key --key-id YOUR_KEY_ID --output text --query PublicKey | base64 -d > key.der

# 3. Set environment variables
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1

# 4. Build and run
mvn clean package && java -jar target/eidasremotesigning-*.jar

# 5. Test (get token, associate key, sign)
# See full commands below
```

---

## 📝 Configuration

### Environment Variables
```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
# Optional:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

### application.yml
```yaml
app:
  aws:
    kms:
      enabled: true
      region: us-east-1
      use-default-credentials: true
```

---

## 🔑 AWS KMS Commands

### Create Keys
```bash
# RSA 2048 (recommended)
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_2048

# RSA 4096 (higher security)
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_4096

# ECC P-256
aws kms create-key --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256
```

### Manage Keys
```bash
# List all keys
aws kms list-keys

# Get key details
aws kms describe-key --key-id KEY_ID

# Create alias
aws kms create-alias --alias-name alias/my-key --target-key-id KEY_ID

# Enable/disable key
aws kms enable-key --key-id KEY_ID
aws kms disable-key --key-id KEY_ID

# Get public key
aws kms get-public-key --key-id KEY_ID
```

---

## 🌐 API Endpoints

### Authentication
```bash
# Register client
POST http://localhost:9000/client-registration
{
  "clientName": "My Client",
  "scopes": ["signing"],
  "grantTypes": ["client_credentials"]
}

# Get token
POST http://localhost:9000/oauth2/token
Authorization: Basic base64(clientId:clientSecret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=signing
```

### KMS Operations
```bash
# List KMS keys
GET http://localhost:9000/api/v1/certificates/aws-kms/keys
Authorization: Bearer TOKEN

# Associate KMS key
POST http://localhost:9000/api/v1/certificates/aws-kms/associate
Authorization: Bearer TOKEN
Content-Type: application/json
{
  "kmsKeyId": "KEY_ID_OR_ARN",
  "certificateBase64": "BASE64_CERT",
  "description": "My Signing Cert"
}
```

### Signing Operations
```bash
# Sign document
POST http://localhost:9000/csc/v2/signatures/signDocument
Authorization: Bearer TOKEN
{
  "clientId": "CLIENT_ID",
  "credentialID": "CREDENTIAL_ID",
  "documentDigest": "BASE64_HASH",
  "hashAlgo": "SHA-256"
}

# Sign hash
POST http://localhost:9000/csc/v2/signatures/signHash
Authorization: Bearer TOKEN
{
  "clientId": "CLIENT_ID",
  "credentialID": "CREDENTIAL_ID",
  "hashAlgo": "SHA-256",
  "signatureData": {
    "hashToSign": ["BASE64_HASH"]
  }
}
```

---

## 🧪 Complete Test Flow

```bash
# Set variables
export KMS_KEY_ID="your-key-id"
export APP_URL="http://localhost:9000"

# 1. Register client
RESPONSE=$(curl -s -X POST $APP_URL/client-registration \
  -H "Content-Type: application/json" \
  -d '{"clientName":"Test","scopes":["signing"],"grantTypes":["client_credentials"]}')

CLIENT_ID=$(echo $RESPONSE | jq -r '.clientId')
CLIENT_SECRET=$(echo $RESPONSE | jq -r '.clientSecret')

# 2. Get token
CREDS=$(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)
TOKEN=$(curl -s -X POST $APP_URL/oauth2/token \
  -H "Authorization: Basic $CREDS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=signing" | jq -r '.access_token')

# 3. Generate certificate (self-signed for testing)
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=Test"
CERT_BASE64=$(openssl x509 -in cert.pem -outform DER | base64 -w 0)

# 4. Associate KMS key
RESPONSE=$(curl -s -X POST $APP_URL/api/v1/certificates/aws-kms/associate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"kmsKeyId\":\"$KMS_KEY_ID\",\"certificateBase64\":\"$CERT_BASE64\",\"description\":\"Test Cert\"}")

CREDENTIAL_ID=$(echo $RESPONSE | jq -r '.id')

# 5. Create test hash
TEST_HASH=$(echo -n "Hello World" | sha256sum | awk '{print $1}')
HASH_BASE64=$(echo -n $TEST_HASH | xxd -r -p | base64)

# 6. Sign
curl -s -X POST $APP_URL/csc/v2/signatures/signDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"clientId\":\"$CLIENT_ID\",\"credentialID\":\"$CREDENTIAL_ID\",\"documentDigest\":\"$HASH_BASE64\",\"hashAlgo\":\"SHA-256\"}" | jq
```

---

## 🔍 Troubleshooting

### Check KMS Configuration
```bash
# Verify KMS client initialization in logs
grep "AWS KMS" logs/application.log

# Test AWS credentials
aws sts get-caller-identity

# Test KMS access
aws kms list-keys --region us-east-1

# Test specific key
aws kms describe-key --key-id YOUR_KEY_ID
```

### Common Errors

| Error | Solution |
|-------|----------|
| "AWS KMS is not enabled" | Set `AWS_KMS_ENABLED=true` |
| "Access Denied" | Check IAM permissions |
| "Key not found" | Verify key ID and region |
| "InvalidKeyUsageException" | Use `SIGN_VERIFY` keys only |

---

## 💰 Cost Calculator

```
Monthly Cost Estimation:
- KMS Key: $1.00/month
- API Calls: $0.15 per 10,000 requests

Examples:
- 10,000 signatures/month: $1.00 + $0.15 = $1.15
- 100,000 signatures/month: $1.00 + $1.50 = $2.50
- 1,000,000 signatures/month: $1.00 + $15.00 = $16.00
```

---

## 📊 IAM Policy Template

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

---

## 🎯 Key Specifications

| Key Spec | Algorithm | Key Size | Use Case |
|----------|-----------|----------|----------|
| RSA_2048 | RSA | 2048 bits | Standard (recommended) |
| RSA_3072 | RSA | 3072 bits | Enhanced security |
| RSA_4096 | RSA | 4096 bits | Maximum security |
| ECC_NIST_P256 | ECDSA | 256 bits | Efficient signing |
| ECC_NIST_P384 | ECDSA | 384 bits | High security |
| ECC_NIST_P521 | ECDSA | 521 bits | Maximum security |

---

## 🔗 Useful Links

- [Full Setup Guide](AWS_KMS_SETUP_GUIDE.md)
- [Integration Guide](AWS_KMS_INTEGRATION.md)
- [AWS KMS Docs](https://docs.aws.amazon.com/kms/)
- [CSC API Spec](https://cloudsignatureconsortium.org/)

---

## 📋 Checklist

### Initial Setup
- [ ] AWS CLI installed and configured
- [ ] IAM policy created and attached
- [ ] KMS key created
- [ ] Public key exported
- [ ] Certificate generated
- [ ] Application configured

### Testing
- [ ] Application starts successfully
- [ ] KMS keys listed via API
- [ ] Key associated with certificate
- [ ] Signing operation successful
- [ ] CloudTrail logs visible

### Production
- [ ] Use IAM roles (not access keys)
- [ ] Real certificate from CA
- [ ] CloudTrail enabled
- [ ] CloudWatch alarms configured
- [ ] Key rotation policy defined
- [ ] Backup procedures documented
