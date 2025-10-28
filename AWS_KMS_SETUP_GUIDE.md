# AWS KMS Setup Guide - Step by Step

This guide walks you through configuring your eIDAS Remote Signing Service to use AWS KMS for key management.

## 📋 Prerequisites

Before you start, ensure you have:

- ✅ AWS Account with admin access
- ✅ AWS CLI installed and configured
- ✅ Java 17+ installed
- ✅ Maven 3.6+ installed
- ✅ This project built successfully

---

## 🚀 Part 1: AWS Setup (20 minutes)

### Step 1: Install and Configure AWS CLI

```bash
# Install AWS CLI (if not already installed)
# For Linux/macOS:
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

### Step 2: Configure AWS Credentials

```bash
# Configure AWS CLI with your credentials
aws configure

# Enter when prompted:
# AWS Access Key ID: YOUR_ACCESS_KEY
# AWS Secret Access Key: YOUR_SECRET_KEY
# Default region name: us-east-1
# Default output format: json

# Verify configuration
aws sts get-caller-identity
```

**Expected output:**
```json
{
    "UserId": "AIDAXXXXXXXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

### Step 3: Create IAM Policy for KMS Access

Create a file named `kms-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMSSigningPermissions",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:CreateKey"
      ],
      "Resource": "*"
    }
  ]
}
```

Create the policy:

```bash
aws iam create-policy \
  --policy-name eIDAS-KMS-Signing-Policy \
  --policy-document file://kms-policy.json
```

**Save the ARN** from the output:
```
arn:aws:iam::123456789012:policy/eIDAS-KMS-Signing-Policy
```

### Step 4: Attach Policy to Your IAM User/Role

**Option A: For IAM User**
```bash
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::123456789012:policy/eIDAS-KMS-Signing-Policy
```

**Option B: For IAM Role (EC2/ECS)**
```bash
aws iam attach-role-policy \
  --role-name YOUR_ROLE_NAME \
  --policy-arn arn:aws:iam::123456789012:policy/eIDAS-KMS-Signing-Policy
```

### Step 5: Create Your First KMS Signing Key

**For RSA Key (Most Common):**
```bash
aws kms create-key \
  --description "eIDAS Remote Signing Production Key" \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --region us-east-1
```

**For Elliptic Curve Key:**
```bash
aws kms create-key \
  --description "eIDAS Remote Signing ECC Key" \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --region us-east-1
```

**Save the KeyId** from the output:
```json
{
    "KeyMetadata": {
        "KeyId": "12345678-1234-1234-1234-123456789012",
        "Arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
}
```

### Step 6: Create an Alias (Optional but Recommended)

```bash
aws kms create-alias \
  --alias-name alias/eidas-signing-key \
  --target-key-id 12345678-1234-1234-1234-123456789012
```

### Step 7: Get the Public Key

```bash
# Get public key from KMS
aws kms get-public-key \
  --key-id 12345678-1234-1234-1234-123456789012 \
  --output text \
  --query PublicKey | base64 -d > kms_public_key.der

# Convert to PEM format
openssl rsa -pubin -inform DER -in kms_public_key.der -outform PEM -out kms_public_key.pem

# View the public key
cat kms_public_key.pem
```

### Step 8: Generate a Certificate

For testing, create a self-signed certificate:

```bash
# Create a config file for the certificate
cat > cert_config.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Your Organization
OU = IT Department
CN = eIDAS Signing Certificate
emailAddress = admin@yourorg.com

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:true
keyUsage = digitalSignature, nonRepudiation
EOF

# Generate CSR (using a placeholder private key since we can't export KMS key)
openssl req -new -key <(openssl genrsa 2048) -out cert.csr -config cert_config.cnf

# Create self-signed certificate using the KMS public key
# Note: For production, you should get this signed by a CA
openssl req -x509 -new -key kms_public_key.pem -out certificate.pem -days 365 -config cert_config.cnf

# Convert certificate to DER format and Base64 encode it
openssl x509 -in certificate.pem -outform DER | base64 -w 0 > certificate_base64.txt

# View the certificate
cat certificate_base64.txt
```

**Note:** For production, you MUST obtain a certificate from a qualified Certificate Authority. This self-signed cert is only for testing.

---

## 🔧 Part 2: Application Configuration (5 minutes)

### Step 1: Update application.yml

Edit `src/main/resources/application.yml`:

```yaml
app:
  aws:
    kms:
      # Enable AWS KMS integration
      enabled: true

      # AWS region where your KMS keys are located
      region: us-east-1

      # Use default AWS credentials chain (recommended for EC2/ECS/Lambda)
      # This will use IAM roles, environment variables, or AWS CLI credentials
      use-default-credentials: true

      # Optional: Explicit credentials (NOT recommended for production)
      # access-key-id: ${AWS_ACCESS_KEY_ID:}
      # secret-access-key: ${AWS_SECRET_ACCESS_KEY:}
```

### Step 2: Set Environment Variables (Alternative)

Instead of editing `application.yml`, you can use environment variables:

```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true

# Optional: If not using default credentials
# export AWS_ACCESS_KEY_ID=your_access_key
# export AWS_SECRET_ACCESS_KEY=your_secret_key
```

### Step 3: Build the Application

```bash
# Clean and build
mvn clean package

# Skip tests if you want faster build
mvn clean package -DskipTests
```

### Step 4: Start the Application

```bash
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

**Verify startup logs:**
```
2025-10-28 ... Initializing AWS KMS client for region: us-east-1
2025-10-28 ... Using AWS default credentials provider chain
2025-10-28 ... AWS KMS client initialized successfully
```

---

## 🧪 Part 3: Testing the Integration (10 minutes)

### Step 1: Register an OAuth2 Client

```bash
curl -X POST http://localhost:9000/client-registration \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "KMS Test Client",
    "scopes": ["signing"],
    "grantTypes": ["client_credentials"]
  }'
```

**Save the response:**
```json
{
  "clientId": "abc123...",
  "clientSecret": "secret456...",
  "clientName": "KMS Test Client"
}
```

### Step 2: Get an Access Token

```bash
# Replace abc123:secret456 with your actual client_id:client_secret
CLIENT_CREDS=$(echo -n "abc123:secret456" | base64)

curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $CLIENT_CREDS" \
  -d "grant_type=client_credentials&scope=signing"
```

**Save the access_token:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Step 3: List Available KMS Keys

```bash
# Set your token
TOKEN="eyJhbGciOiJSUzI1..."

curl -X GET http://localhost:9000/api/v1/certificates/aws-kms/keys \
  -H "Authorization: Bearer $TOKEN"
```

**Expected response:**
```json
[
  {
    "keyId": "12345678-1234-1234-1234-123456789012",
    "keyArn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "description": "eIDAS Remote Signing Production Key",
    "keySpec": "RSA_2048",
    "enabled": true,
    "creationDate": "2025-10-28T10:00:00Z"
  }
]
```

### Step 4: Associate KMS Key with Certificate

```bash
# Read the Base64 certificate
CERT_BASE64=$(cat certificate_base64.txt)

# Associate the KMS key
curl -X POST http://localhost:9000/api/v1/certificates/aws-kms/associate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"kmsKeyId\": \"12345678-1234-1234-1234-123456789012\",
    \"certificateBase64\": \"$CERT_BASE64\",
    \"description\": \"Production Signing Certificate\",
    \"awsRegion\": \"us-east-1\"
  }"
```

**Expected response:**
```json
{
  "id": "cert-xyz789",
  "subjectDN": "CN=eIDAS Signing Certificate,O=Your Organization,C=US",
  "issuerDN": "CN=eIDAS Signing Certificate,O=Your Organization,C=US",
  "serialNumber": "123456789",
  "keyAlgorithm": "RSA",
  "keySize": 2048,
  "description": "Production Signing Certificate",
  "storageType": "AWSKMS",
  "active": true,
  "selfSigned": true
}
```

**Save the certificate ID (credentialID):** `cert-xyz789`

### Step 5: Test Signing Operation

```bash
# Create a test document hash (SHA-256 of "Hello World")
TEST_HASH=$(echo -n "Hello World" | sha256sum | awk '{print $1}')
TEST_HASH_BASE64=$(echo -n $TEST_HASH | xxd -r -p | base64)

# Sign the hash using AWS KMS
curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"abc123\",
    \"credentialID\": \"cert-xyz789\",
    \"documentDigest\": \"$TEST_HASH_BASE64\",
    \"hashAlgo\": \"SHA-256\",
    \"signatureAttributes\": {
      \"signatureType\": \"XAdES\"
    }
  }"
```

**Expected response:**
```json
{
  "transactionID": "tx-12345",
  "signedDocumentDigest": "base64_digest...",
  "signatureAlgorithm": "SHA256withRSA",
  "certificate": "base64_certificate..."
}
```

**✅ Success!** If you see a signature response, AWS KMS integration is working!

---

## 🎯 Part 4: Verification and Troubleshooting

### Verify the Signature

```bash
# The signature can be verified using OpenSSL
# This is a conceptual example - actual verification depends on your signature format

# Extract signature from response (replace with actual base64 signature)
SIGNATURE_BASE64="signature_from_response"
echo "$SIGNATURE_BASE64" | base64 -d > signature.bin

# Verify using the public key
echo -n "Hello World" | openssl dgst -sha256 -verify kms_public_key.pem -signature signature.bin
```

### Check Application Logs

```bash
# View logs for KMS activity
tail -f logs/application.log | grep KMS
```

### Common Issues and Solutions

#### Issue 1: "AWS KMS is not enabled or configured"

**Solution:**
```bash
# Check application.yml
grep -A 5 "aws:" src/main/resources/application.yml

# Or set environment variable
export AWS_KMS_ENABLED=true
```

#### Issue 2: "Access Denied" when calling KMS

**Solution:**
```bash
# Verify IAM permissions
aws kms describe-key --key-id YOUR_KEY_ID

# If access denied, re-attach the policy
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::ACCOUNT:policy/eIDAS-KMS-Signing-Policy
```

#### Issue 3: "KMS key not found or not enabled"

**Solution:**
```bash
# List your keys
aws kms list-keys

# Check key status
aws kms describe-key --key-id YOUR_KEY_ID

# Enable key if disabled
aws kms enable-key --key-id YOUR_KEY_ID
```

#### Issue 4: "Region mismatch"

**Solution:**
Ensure all regions match:
```bash
# Check AWS CLI region
aws configure get region

# Check application configuration
grep "region:" src/main/resources/application.yml

# Create key in correct region
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_2048 --region us-east-1
```

---

## 📊 Monitoring and Logging

### Enable CloudTrail for KMS

```bash
# Create CloudTrail trail (if not exists)
aws cloudtrail create-trail \
  --name kms-signing-trail \
  --s3-bucket-name your-cloudtrail-bucket

# Start logging
aws cloudtrail start-logging --name kms-signing-trail
```

### View KMS API Calls

```bash
# View recent KMS Sign operations
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Sign \
  --max-results 10
```

### Application-Level Logging

Add to `application.yml`:
```yaml
logging:
  level:
    com.wpanther.eidasremotesigning.service.AWSKMSService: DEBUG
    com.wpanther.eidasremotesigning.config.AWSKMSConfig: DEBUG
```

---

## 🔐 Production Deployment Checklist

### Security

- [ ] Use IAM roles (not access keys) on EC2/ECS/Lambda
- [ ] Enable CloudTrail logging
- [ ] Implement key rotation policy
- [ ] Use separate KMS keys for dev/staging/production
- [ ] Restrict KMS key policies to specific IAM principals
- [ ] Enable AWS Config for compliance tracking

### High Availability

- [ ] Use multi-region KMS keys (optional)
- [ ] Implement retry logic for transient failures
- [ ] Set up CloudWatch alarms for KMS errors
- [ ] Test failover scenarios

### Cost Optimization

- [ ] Monitor KMS API call counts
- [ ] Implement caching where appropriate
- [ ] Set up billing alerts

### Compliance

- [ ] Obtain certificates from qualified CA (not self-signed)
- [ ] Document key management procedures
- [ ] Implement audit log retention policy
- [ ] Regular security reviews

---

## 📱 Quick Reference Commands

```bash
# List all KMS keys
aws kms list-keys --region us-east-1

# Describe specific key
aws kms describe-key --key-id YOUR_KEY_ID

# Get public key
aws kms get-public-key --key-id YOUR_KEY_ID

# Test signing (from AWS CLI)
echo -n "test data" | aws kms sign \
  --key-id YOUR_KEY_ID \
  --message-type RAW \
  --signing-algorithm RSASSA_PKCS1_V1_5_SHA_256 \
  --message fileb:///dev/stdin

# View CloudTrail KMS events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::KMS::Key
```

---

## 🎓 Next Steps

1. **Obtain Real Certificates** - Replace self-signed cert with CA-issued certificate
2. **Set Up Monitoring** - Configure CloudWatch alarms
3. **Load Testing** - Test with realistic signing volumes
4. **Disaster Recovery** - Document key recovery procedures
5. **Integration** - Connect to your frontend applications

---

## 📚 Additional Resources

- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [CSC API v2.0 Specification](https://cloudsignatureconsortium.org/resources/csc-api-v2-0/)
- [eIDAS Regulation Overview](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eIDAS)

---

## ✅ Configuration Complete!

Your eIDAS Remote Signing Service is now configured to use AWS KMS for secure key management.

**Summary:**
- ✅ AWS KMS keys created
- ✅ IAM permissions configured
- ✅ Application configured
- ✅ Certificates associated
- ✅ Signing tested and working

You can now use AWS KMS for production-grade digital signatures with your eIDAS-compliant service!
