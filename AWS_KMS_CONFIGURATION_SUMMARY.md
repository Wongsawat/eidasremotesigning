# AWS KMS Configuration Summary

## ✅ What You Need to Know

### 🎯 **Simple Answer: How to Configure AWS KMS**

1. **Enable AWS KMS in application configuration**
2. **Create a signing key in AWS KMS**
3. **Get an OAuth2 token**
4. **Associate the KMS key with a certificate via API**
5. **Start signing!**

---

## 🚀 Fastest Path (10 Minutes)

### Step 1: Enable KMS (1 minute)

**Option A: Environment Variables (Recommended)**
```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
```

**Option B: Edit application.yml**
```yaml
app:
  aws:
    kms:
      enabled: true
      region: us-east-1
      use-default-credentials: true
```

### Step 2: Create AWS KMS Key (2 minutes)

```bash
# Install AWS CLI if needed
brew install awscli  # macOS
# or
sudo apt install awscli  # Ubuntu

# Configure AWS credentials
aws configure

# Create signing key
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --description "eIDAS Signing Key"
```

**Save the KeyId from output:**
```json
{
  "KeyMetadata": {
    "KeyId": "12345678-abcd-1234-abcd-123456789012"
  }
}
```

### Step 3: Generate Test Certificate (2 minutes)

```bash
# Get public key from KMS
aws kms get-public-key \
  --key-id YOUR_KEY_ID \
  --output text \
  --query PublicKey | base64 -d > kms_public.der

# Create self-signed certificate (for testing)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout temp.key -out cert.pem -days 365 \
  -subj "/CN=Test Signing Cert/O=Test Org/C=US"

# Convert to Base64
openssl x509 -in cert.pem -outform DER | base64 -w 0 > cert_base64.txt
```

### Step 4: Start Application (1 minute)

```bash
mvn clean package
java -jar target/eidasremotesigning-0.0.1-SNAPSHOT.jar
```

### Step 5: Use the API (4 minutes)

```bash
# A. Register OAuth2 client
curl -X POST http://localhost:9000/client-registration \
  -H "Content-Type: application/json" \
  -d '{"clientName":"Test","scopes":["signing"],"grantTypes":["client_credentials"]}'

# Save: client_id and client_secret

# B. Get access token
curl -X POST http://localhost:9000/oauth2/token \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=signing"

# Save: access_token

# C. Associate KMS key
curl -X POST http://localhost:9000/api/v1/certificates/aws-kms/associate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"kmsKeyId\": \"YOUR_KEY_ID\",
    \"certificateBase64\": \"$(cat cert_base64.txt)\",
    \"description\": \"My Signing Cert\"
  }"

# Save: credential_id from response

# D. Sign a document
echo -n "Hello World" | sha256sum | awk '{print $1}' | xxd -r -p | base64 > hash.txt

curl -X POST http://localhost:9000/csc/v2/signatures/signDocument \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"YOUR_CLIENT_ID\",
    \"credentialID\": \"YOUR_CREDENTIAL_ID\",
    \"documentDigest\": \"$(cat hash.txt)\",
    \"hashAlgo\": \"SHA-256\"
  }"
```

**🎉 Done!** You're now signing with AWS KMS!

---

## 📚 Documentation Reference

| Document | Purpose | When to Use |
|----------|---------|-------------|
| **[AWS_KMS_SETUP_GUIDE.md](AWS_KMS_SETUP_GUIDE.md)** | Complete step-by-step guide | First-time setup |
| **[AWS_KMS_QUICK_REFERENCE.md](AWS_KMS_QUICK_REFERENCE.md)** | Quick commands & troubleshooting | Daily operations |
| **[AWS_KMS_INTEGRATION.md](AWS_KMS_INTEGRATION.md)** | Architecture & best practices | Understanding internals |
| **[AWS_KMS_QUICKSTART.md](AWS_KMS_QUICKSTART.md)** | 5-step quick start | Fastest setup |
| **This file** | Configuration summary | Quick overview |

---

## 🔑 Key Configuration Points

### 1. Application Configuration

The application reads AWS KMS settings from:

**Priority Order:**
1. Environment variables (highest)
2. System properties
3. application.yml (lowest)

**Required Settings:**
```yaml
app.aws.kms.enabled=true      # Must be true
app.aws.kms.region=us-east-1  # Your AWS region
```

**Optional Settings:**
```yaml
app.aws.kms.use-default-credentials=true  # Use IAM role/env vars
app.aws.kms.access-key-id=KEY             # Only if not using default
app.aws.kms.secret-access-key=SECRET      # Only if not using default
```

### 2. AWS Credentials

**Best Practice (Production):**
```bash
# Use IAM roles on EC2/ECS/Lambda - No credentials in code!
# Nothing to configure - just works!
```

**Development:**
```bash
# Option 1: AWS CLI credentials
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1
```

### 3. IAM Permissions

Minimum required permissions:
```json
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
```

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│          eIDAS Remote Signing Service               │
│                                                     │
│  ┌───────────────────────────────────────────┐    │
│  │   Your Application Code                   │    │
│  │   (Controllers, Services)                 │    │
│  └───────────────┬───────────────────────────┘    │
│                  │                                 │
│  ┌───────────────▼───────────────────────────┐    │
│  │   SigningCertificateService              │    │
│  │   - Manages certificate associations     │    │
│  └───────────────┬───────────────────────────┘    │
│                  │                                 │
│  ┌───────────────▼───────────────────────────┐    │
│  │   AWSKMSService                           │    │
│  │   - signDigest()                          │    │
│  │   - getPublicKey()                        │    │
│  │   - listSigningKeys()                     │    │
│  └───────────────┬───────────────────────────┘    │
│                  │                                 │
│  ┌───────────────▼───────────────────────────┐    │
│  │   AWS SDK KmsClient                       │    │
│  │   - AWS API calls                         │    │
│  └───────────────┬───────────────────────────┘    │
└──────────────────┼─────────────────────────────────┘
                   │
                   │ HTTPS
                   │
        ┌──────────▼──────────┐
        │                     │
        │   AWS KMS           │
        │   (Cloud HSM)       │
        │                     │
        │  Private keys never │
        │  leave AWS!         │
        └─────────────────────┘
```

---

## 🔒 Security Best Practices

### ✅ DO

1. **Use IAM Roles** on AWS infrastructure (EC2, ECS, Lambda)
2. **Enable CloudTrail** for audit logging
3. **Use separate keys** for dev/staging/production
4. **Obtain certificates from qualified CA** (not self-signed)
5. **Set up key rotation** policies
6. **Monitor KMS API usage** via CloudWatch

### ❌ DON'T

1. **Don't hardcode credentials** in application.yml
2. **Don't use root AWS account** credentials
3. **Don't share KMS keys** across environments
4. **Don't use self-signed certs** in production
5. **Don't forget to test** key deletion scenarios

---

## 🎛️ Environment-Specific Configuration

### Development
```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
# Uses: ~/.aws/credentials
```

### Staging
```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
# Uses: EC2 IAM role for staging
```

### Production
```bash
export AWS_KMS_ENABLED=true
export AWS_REGION=us-east-1
export AWS_USE_DEFAULT_CREDENTIALS=true
# Uses: ECS Task Role for production
# Plus: CloudTrail, CloudWatch, separate KMS keys
```

---

## 🧪 Verification Checklist

After configuration, verify:

- [ ] Application starts without errors
- [ ] Log shows: "AWS KMS client initialized successfully"
- [ ] Can list KMS keys via API: `GET /api/v1/certificates/aws-kms/keys`
- [ ] Can associate a key: `POST /api/v1/certificates/aws-kms/associate`
- [ ] Can sign a document: `POST /csc/v2/signatures/signDocument`
- [ ] CloudTrail shows KMS Sign events (if enabled)

---

## 🆘 Quick Troubleshooting

### "AWS KMS is not enabled or configured"
```bash
# Check configuration
grep -A 5 "aws:" src/main/resources/application.yml

# Or set environment variable
export AWS_KMS_ENABLED=true
```

### "Access Denied" errors
```bash
# Test AWS credentials
aws sts get-caller-identity

# Test KMS access
aws kms list-keys

# Check IAM policy is attached
aws iam list-attached-user-policies --user-name YOUR_USER
```

### "Key not found"
```bash
# List keys in your region
aws kms list-keys --region us-east-1

# Check key details
aws kms describe-key --key-id YOUR_KEY_ID
```

---

## 💰 Cost Estimate

**Typical costs for AWS KMS:**

| Usage | Monthly Cost |
|-------|--------------|
| 1 key + 10k signatures | ~$1.15 |
| 1 key + 100k signatures | ~$2.50 |
| 1 key + 1M signatures | ~$16.00 |
| 5 keys + 100k signatures | ~$6.50 |

**Breakdown:**
- $1.00/key/month
- $0.03 per 10,000 API calls (Sign, GetPublicKey, etc.)

---

## 📞 Next Steps

1. **Set up AWS KMS** using [AWS_KMS_SETUP_GUIDE.md](AWS_KMS_SETUP_GUIDE.md)
2. **Test signing** using the quick reference
3. **Integrate with your apps** using the CSC API
4. **Set up monitoring** with CloudWatch
5. **Go to production** with real certificates

---

## 🎓 Summary

**What you've learned:**
- ✅ AWS KMS requires just 3 configuration settings
- ✅ Keys are created in AWS, not in the application
- ✅ Certificates are associated via REST API
- ✅ No PIN required - IAM handles authentication
- ✅ Signing is transparent - same API as PKCS#11

**The configuration is:** `enabled=true`, `region`, and `credentials` - that's it!

---

**Ready to start?** → [AWS_KMS_SETUP_GUIDE.md](AWS_KMS_SETUP_GUIDE.md)
