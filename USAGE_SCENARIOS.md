# AiKey CLI Usage Scenarios Guide

**Version:** 0.4.0-alpha.1
**Target Audience:** Developers, DevOps Engineers, Security Teams
**Last Updated:** February 15, 2026

---

## Table of Contents

1. [Individual Developer Workflows](#individual-developer-workflows)
2. [Team Collaboration Scenarios](#team-collaboration-scenarios)
3. [DevOps & CI/CD Integration](#devops--cicd-integration)
4. [Security & Compliance](#security--compliance)
5. [Multi-Environment Management](#multi-environment-management)
6. [Emergency & Recovery Scenarios](#emergency--recovery-scenarios)
7. [Migration & Onboarding](#migration--onboarding)

---

## Individual Developer Workflows

### Scenario 1: Daily Development with Multiple API Keys

**Context:** You're a full-stack developer working with GitHub, AWS, OpenAI, and Stripe APIs.

**Setup:**
```bash
# Initialize vault once
ak init
# Set Master Password: ********

# Add all your API keys
ak add github-personal-token
ak add aws-access-key
ak add aws-secret-key
ak add openai-api-key
ak add stripe-test-key
ak add stripe-prod-key
```

**Daily Usage:**

```bash
# Morning: Push code to GitHub
ak exec --env GITHUB_TOKEN=github-personal-token -- git push origin feature/new-api

# Midday: Test AWS deployment
ak exec \
  --env AWS_ACCESS_KEY_ID=aws-access-key \
  --env AWS_SECRET_ACCESS_KEY=aws-secret-key \
  -- aws s3 sync ./build s3://my-bucket

# Afternoon: Test OpenAI integration
ak exec --env OPENAI_API_KEY=openai-api-key -- python test_ai_features.py

# Evening: Process test payment
ak exec --env STRIPE_KEY=stripe-test-key -- npm run test:payments
```

**Benefits:**
- No `.env` files in your repository
- No accidental commits of secrets
- Quick access without memorizing keys
- Automatic clipboard clearing prevents shoulder surfing

---

### Scenario 2: Switching Between Projects

**Context:** You work on multiple client projects, each with different credentials.

**Organization Strategy:**
```bash
# Project A credentials
ak add projecta-db-password
ak add projecta-api-key
ak add projecta-aws-key

# Project B credentials
ak add projectb-db-password
ak add projectb-api-key
ak add projectb-gcp-key

# List all secrets to verify
ak list
```

**Project-Specific Execution:**
```bash
# Working on Project A
ak exec \
  --env DB_PASSWORD=projecta-db-password \
  --env API_KEY=projecta-api-key \
  -- npm run dev

# Switch to Project B
ak exec \
  --env DB_PASSWORD=projectb-db-password \
  --env API_KEY=projectb-api-key \
  -- npm run dev
```

**Export for Backup:**
```bash
# Backup Project A secrets
ak export "projecta-*" ~/backups/projecta-secrets.akb

# Backup Project B secrets
ak export "projectb-*" ~/backups/projectb-secrets.akb
```

---

### Scenario 3: Onboarding to New Machine

**Context:** You got a new laptop and need to transfer all your secrets securely.

**On Old Machine:**
```bash
# Export all secrets
ak export "*" ~/Desktop/all-secrets-backup.akb

# Copy to USB drive or secure cloud storage
cp ~/Desktop/all-secrets-backup.akb /Volumes/USB/
```

**On New Machine:**
```bash
# Install ak
cargo install --path .

# Initialize new vault
ak init
# Use the SAME master password

# Import all secrets
ak import /Volumes/USB/all-secrets-backup.akb

# Verify
ak list
```

**Time Saved:** 5 minutes vs. 2+ hours manually copying secrets

---

## Team Collaboration Scenarios

### Scenario 4: Sharing Development Credentials

**Context:** Your team needs shared access to staging environment credentials.

**Team Lead Setup:**
```bash
# Create shared credentials
ak add staging-db-password
ak add staging-api-key
ak add staging-aws-key

# Export for team
ak export "staging-*" team-staging-credentials.akb

# Share via secure channel (encrypted email, 1Password, etc.)
```

**Team Member Setup:**
```bash
# Initialize personal vault
ak init

# Import shared credentials
ak import team-staging-credentials.akb

# Add personal credentials
ak add github-personal-token
ak add personal-aws-key

# Now you have both shared and personal secrets
ak list
```

**Security Note:** Each team member uses their own master password. The `.akb` file is encrypted with a shared password communicated separately.

---

### Scenario 5: Rotating Shared Credentials

**Context:** A team member leaves, and you need to rotate all shared credentials.

**Process:**
```bash
# 1. Generate new credentials at each service provider
# (GitHub, AWS, etc.)

# 2. Update in vault
ak update staging-db-password
ak update staging-api-key
ak update staging-aws-key

# 3. Export updated credentials
ak export "staging-*" team-staging-credentials-2026-02.akb

# 4. Distribute to remaining team members
# 5. Team members import (will update existing secrets)
ak import team-staging-credentials-2026-02.akb

# 6. Verify version incremented
# (Future feature: ak show staging-api-key --metadata)
```

**Audit Trail:**
```bash
# Check who accessed what (future feature)
ak audit list --operation get --since "30 days ago"
```

---

## DevOps & CI/CD Integration

### Scenario 6: GitHub Actions Deployment

**Context:** Deploy application with secrets from vault.

**GitHub Actions Workflow:**
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install ak
        run: |
          cargo install --git https://github.com/AiKey-Founder/aikey-labs

      - name: Setup vault
        run: |
          echo "${{ secrets.AK_MASTER_PASSWORD }}" | ak --password-stdin init
          echo "${{ secrets.AK_VAULT_BACKUP }}" | base64 -d > vault.akb
          echo "${{ secrets.AK_MASTER_PASSWORD }}" | ak --password-stdin import vault.akb

      - name: Deploy with secrets
        run: |
          echo "${{ secrets.AK_MASTER_PASSWORD }}" | ak --password-stdin exec \
            --env AWS_ACCESS_KEY_ID=prod-aws-key \
            --env AWS_SECRET_ACCESS_KEY=prod-aws-secret \
            --env DB_PASSWORD=prod-db-password \
            -- ./deploy.sh
```

**Setup GitHub Secrets:**
```bash
# 1. Export vault
ak export "*" prod-vault.akb

# 2. Base64 encode for GitHub
base64 prod-vault.akb > prod-vault.akb.b64

# 3. Add to GitHub Secrets:
# - AK_MASTER_PASSWORD: your master password
# - AK_VAULT_BACKUP: contents of prod-vault.akb.b64
```

---

### Scenario 7: Docker Container Secrets

**Context:** Run containerized applications with secrets.

**Dockerfile:**
```dockerfile
FROM rust:1.70 as builder
RUN cargo install --git https://github.com/AiKey-Founder/aikey-labs

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/ak /usr/local/bin/
COPY app /app
WORKDIR /app

# Vault will be mounted at runtime
ENTRYPOINT ["ak", "exec", \
  "--env", "DB_PASSWORD=prod-db-password", \
  "--env", "API_KEY=prod-api-key", \
  "--", "node", "server.js"]
```

**Run Container:**
```bash
# Export vault
ak export "*" prod-vault.akb

# Run with vault mounted
docker run -it \
  -v $(pwd)/prod-vault.akb:/vault.akb:ro \
  -e AK_VAULT_PATH=/vault.akb \
  myapp:latest
```

---

### Scenario 8: Kubernetes Secrets Management

**Context:** Manage secrets for Kubernetes deployments.

**Setup Script:**
```bash
#!/bin/bash
# k8s-secrets-setup.sh

# Export secrets for each namespace
ak export "prod-*" prod-secrets.akb
ak export "staging-*" staging-secrets.akb

# Create Kubernetes secrets
kubectl create secret generic ak-vault \
  --from-file=vault.akb=prod-secrets.akb \
  --namespace=production

kubectl create secret generic ak-vault \
  --from-file=vault.akb=staging-secrets.akb \
  --namespace=staging
```

**Deployment YAML:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      initContainers:
      - name: setup-secrets
        image: myapp:latest
        command: ["/bin/sh", "-c"]
        args:
          - |
            echo "$AK_PASSWORD" | ak --password-stdin import /vault/vault.akb
        env:
        - name: AK_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ak-master-password
              key: password
        volumeMounts:
        - name: vault
          mountPath: /vault

      containers:
      - name: app
        image: myapp:latest
        command: ["ak", "exec",
          "--env", "DB_PASSWORD=prod-db-password",
          "--", "node", "server.js"]

      volumes:
      - name: vault
        secret:
          secretName: ak-vault
```

---

## Security & Compliance

### Scenario 9: Security Audit & Compliance

**Context:** Your company requires audit trails for all secret access.

**Enable Audit Logging:**
```bash
# Audit logging is automatic in v0.4.0-alpha.1
# All operations are logged with HMAC verification

# View audit log (future feature)
ak audit list

# Verify integrity
ak audit verify
```

**Generate Compliance Report:**
```bash
# Export audit log for review (future feature)
ak audit export --since "2026-01-01" --format json > audit-2026-q1.json

# Check for suspicious activity
ak audit analyze --anomalies
```

**Audit Log Contents:**
```
Timestamp: 2026-02-15 10:30:45
Operation: get
Alias: prod-db-password
Success: true
HMAC: a3f5b8c9d2e1f4a7b6c5d8e9f2a1b4c7...
User: developer@company.com (future feature)
IP: 192.168.1.100 (future feature)
```

---

### Scenario 10: Incident Response

**Context:** A developer's laptop was stolen. You need to rotate all credentials they had access to.

**Immediate Actions:**
```bash
# 1. List all secrets (to know what to rotate)
ak list

# 2. Identify secrets the developer had access to
# (Check team documentation or shared credential lists)

# 3. Rotate at service providers
# - GitHub: Revoke old token, generate new
# - AWS: Deactivate old keys, create new
# - Database: Change password

# 4. Update vault
ak update github-team-token
ak update aws-team-key
ak update staging-db-password

# 5. Export updated credentials
ak export "*" team-credentials-post-incident.akb

# 6. Distribute to team
# (via secure channel)

# 7. Verify old credentials no longer work
ak exec --env OLD_KEY=old-github-token -- git ls-remote
# Should fail with 401 Unauthorized
```

**Post-Incident:**
```bash
# Review audit logs
ak audit list --since "incident-date" --operation get

# Document lessons learned
# Update security procedures
```

---

### Scenario 11: Penetration Testing

**Context:** Security team needs to test application with production-like credentials.

**Setup Isolated Environment:**
```bash
# Create pentest-specific credentials at providers
# (Never use actual production credentials)

# Add to vault with clear naming
ak add pentest-db-password
ak add pentest-api-key
ak add pentest-aws-key

# Export for pentest team
ak export "pentest-*" pentest-credentials.akb

# Share securely with pentest team
```

**Pentest Team Usage:**
```bash
# Import credentials
ak import pentest-credentials.akb

# Run security tests
ak exec \
  --env DB_PASSWORD=pentest-db-password \
  --env API_KEY=pentest-api-key \
  -- python security_scanner.py

# After testing, rotate all pentest credentials
```

---

## Multi-Environment Management

### Scenario 12: Development → Staging → Production Pipeline

**Context:** Manage secrets across three environments with different credentials.

**Organization:**
```bash
# Development environment
ak add dev-db-password
ak add dev-api-key
ak add dev-aws-key

# Staging environment
ak add staging-db-password
ak add staging-api-key
ak add staging-aws-key

# Production environment
ak add prod-db-password
ak add prod-api-key
ak add prod-aws-key
```

**Environment-Specific Scripts:**

**dev.sh:**
```bash
#!/bin/bash
ak exec \
  --env DB_PASSWORD=dev-db-password \
  --env API_KEY=dev-api-key \
  --env AWS_ACCESS_KEY_ID=dev-aws-key \
  -- npm run dev
```

**staging.sh:**
```bash
#!/bin/bash
ak exec \
  --env DB_PASSWORD=staging-db-password \
  --env API_KEY=staging-api-key \
  --env AWS_ACCESS_KEY_ID=staging-aws-key \
  -- npm run start:staging
```

**prod.sh:**
```bash
#!/bin/bash
# Extra confirmation for production
read -p "Deploy to PRODUCTION? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
  echo "Deployment cancelled"
  exit 1
fi

ak exec \
  --env DB_PASSWORD=prod-db-password \
  --env API_KEY=prod-api-key \
  --env AWS_ACCESS_KEY_ID=prod-aws-key \
  -- npm run start:production
```

**Usage:**
```bash
# Development
./dev.sh

# Staging
./staging.sh

# Production (with confirmation)
./prod.sh
```

---

### Scenario 13: Multi-Region Deployment

**Context:** Deploy to multiple AWS regions with region-specific credentials.

**Setup:**
```bash
# US East credentials
ak add aws-us-east-key
ak add aws-us-east-secret

# EU West credentials
ak add aws-eu-west-key
ak add aws-eu-west-secret

# Asia Pacific credentials
ak add aws-ap-key
ak add aws-ap-secret
```

**Deployment Script:**
```bash
#!/bin/bash
# deploy-multi-region.sh

regions=("us-east" "eu-west" "ap")

for region in "${regions[@]}"; do
  echo "Deploying to $region..."

  ak exec \
    --env AWS_ACCESS_KEY_ID=aws-${region}-key \
    --env AWS_SECRET_ACCESS_KEY=aws-${region}-secret \
    -- aws s3 sync ./build s3://myapp-${region}

  echo "✓ $region deployment complete"
done
```

---

## Emergency & Recovery Scenarios

### Scenario 14: Forgot Master Password

**Context:** You forgot your master password and need to recover access.

**If You Have a Backup:**
```bash
# 1. You CANNOT recover the password
# 2. You CANNOT decrypt the vault without the password
# 3. Your only option is to restore from an unencrypted backup

# If you have secrets documented elsewhere:
# - Reinitialize vault
ak init
# Set NEW master password

# - Re-add all secrets manually
ak add github-token
# ... (repeat for all secrets)
```

**Prevention:**
```bash
# Store master password in a password manager
# - 1Password
# - Bitwarden
# - LastPass

# Or write it down and store in a physical safe
```

**Important:** There is NO password recovery mechanism. This is by design for security.

---

### Scenario 15: Corrupted Vault Recovery

**Context:** Your vault.db file is corrupted.

**Symptoms:**
```bash
$ ak list
Error: "Failed to open database: database disk image is malformed"
```

**Recovery Steps:**
```bash
# 1. Check if you have a recent .akb backup
ls -lh ~/backups/*.akb

# 2. Initialize new vault
mv ~/.aikey/vault.db ~/.aikey/vault.db.corrupted
ak init

# 3. Import from backup
ak import ~/backups/vault-20260214.akb

# 4. Verify all secrets restored
ak list

# 5. Test a few secrets
ak get github-token --timeout 0
```

**Prevention:**
```bash
# Automated daily backup
# Add to crontab: crontab -e
0 2 * * * /home/user/scripts/backup-vault.sh

# backup-vault.sh:
#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR="$HOME/vault-backups"
mkdir -p "$BACKUP_DIR"

echo "$MASTER_PASSWORD" | ak --password-stdin export "*" "$BACKUP_DIR/vault-$DATE.akb"

# Keep last 30 days
find "$BACKUP_DIR" -name "vault-*.akb" -mtime +30 -delete
```

---

### Scenario 16: Emergency Credential Rotation

**Context:** A security breach requires immediate rotation of all credentials.

**Rapid Rotation Process:**
```bash
# 1. List all secrets to rotate
ak list > secrets-to-rotate.txt

# 2. For each service, generate new credentials
# (GitHub, AWS, databases, etc.)

# 3. Update vault (can be scripted)
while read alias; do
  echo "Rotating $alias..."
  # Prompt for new value
  ak update "$alias"
done < secrets-to-rotate.txt

# 4. Export updated vault
ak export "*" vault-post-rotation-$(date +%Y%m%d).akb

# 5. Distribute to team immediately
# 6. Verify old credentials are revoked at providers
# 7. Test applications with new credentials
```

**Parallel Rotation Script:**
```bash
#!/bin/bash
# rotate-all.sh

# Services to rotate
services=("github" "aws" "database" "stripe")

for service in "${services[@]}"; do
  echo "=== Rotating $service credentials ==="

  # Generate new credential at provider (manual or API)
  # Then update in vault
  ak update "${service}-api-key"

  # Test new credential
  ak exec --env KEY="${service}-api-key" -- ./test-${service}.sh

  if [ $? -eq 0 ]; then
    echo "✓ $service rotation successful"
  else
    echo "✗ $service rotation FAILED - manual intervention required"
  fi
done
```

---

## Migration & Onboarding

### Scenario 17: Migrating from .env Files

**Context:** Your project currently uses `.env` files, and you want to migrate to `ak`.

**Current State:**
```bash
# .env file (INSECURE - in git history)
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
DATABASE_URL=postgresql://user:password@localhost/db
```

**Migration Steps:**

**1. Initialize vault:**
```bash
ak init
```

**2. Import secrets from .env:**
```bash
#!/bin/bash
# migrate-from-env.sh

# Read .env file
while IFS='=' read -r key value; do
  # Skip comments and empty lines
  [[ $key =~ ^#.*$ ]] && continue
  [[ -z $key ]] && continue

  # Convert to lowercase with hyphens
  alias=$(echo "$key" | tr '[:upper:]' '[:lower:]' | tr '_' '-')

  # Add to vault
  echo "Migrating $key -> $alias"
  echo -e "$MASTER_PASSWORD\n$value" | ak add "$alias"
done < .env

echo "Migration complete!"
```

**3. Update application code:**

**Before:**
```javascript
// config.js
require('dotenv').config();

const config = {
  githubToken: process.env.GITHUB_TOKEN,
  awsKey: process.env.AWS_ACCESS_KEY_ID,
  dbUrl: process.env.DATABASE_URL
};
```

**After:**
```javascript
// config.js
// No changes needed! Environment variables still work

const config = {
  githubToken: process.env.GITHUB_TOKEN,
  awsKey: process.env.AWS_ACCESS_KEY_ID,
  dbUrl: process.env.DATABASE_URL
};
```

**4. Update run scripts:**

**Before:**
```json
{
  "scripts": {
    "dev": "node server.js",
    "start": "node server.js"
  }
}
```

**After:**
```json
{
  "scripts": {
    "dev": "ak exec --env GITHUB_TOKEN=github-token --env AWS_ACCESS_KEY_ID=aws-access-key-id --env DATABASE_URL=database-url -- node server.js",
    "start": "ak exec --env GITHUB_TOKEN=github-token --env AWS_ACCESS_KEY_ID=aws-access-key-id --env DATABASE_URL=database-url -- node server.js"
  }
}
```

**5. Remove .env file:**
```bash
# Remove from git
git rm .env
git rm .env.example

# Add to .gitignore (if not already)
echo ".env" >> .gitignore

# Commit
git add .gitignore
git commit -m "Migrate to ak secret management"
```

---

### Scenario 18: Migrating from 1Password CLI

**Context:** You're currently using 1Password CLI and want to switch to `ak`.

**Export from 1Password:**
```bash
# Export items (requires 1Password CLI)
op item list --vault "Development" --format json > 1password-export.json
```

**Import to ak:**
```bash
#!/bin/bash
# import-from-1password.sh

# Parse JSON and add to ak
jq -r '.[] | "\(.title)|\(.fields[] | select(.label=="password") | .value)"' 1password-export.json | \
while IFS='|' read -r title password; do
  alias=$(echo "$title" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
  echo "Importing $title -> $alias"
  echo -e "$MASTER_PASSWORD\n$password" | ak add "$alias"
done

# Securely delete export
shred -u 1password-export.json
```

---

### Scenario 19: Team Onboarding

**Context:** New developer joins the team and needs access to shared credentials.

**Onboarding Checklist:**

**Day 1 - Setup:**
```bash
# 1. Install ak
cargo install --path .

# 2. Initialize personal vault
ak init
# Use a STRONG, UNIQUE master password

# 3. Receive shared credentials file from team lead
# (via secure channel: encrypted email, Slack DM, etc.)

# 4. Import shared credentials
ak import team-shared-credentials.akb

# 5. Verify access
ak list
```

**Day 1 - Add Personal Credentials:**
```bash
# Add personal GitHub token
ak add github-personal-token

# Add personal AWS keys (if applicable)
ak add personal-aws-key
ak add personal-aws-secret

# Test access
ak exec --env GITHUB_TOKEN=github-personal-token -- git clone <repo>
```

**Week 1 - Setup Backup:**
```bash
# Export personal vault
ak export "*" ~/Dropbox/vault-backup-$(date +%Y%m%d).akb

# Setup automated backup (add to crontab)
0 2 * * 0 /home/user/scripts/backup-vault.sh
```

**Onboarding Documentation:**
```markdown
# Secret Management Onboarding

## Required Tools
- [ ] Install Rust
- [ ] Install ak CLI
- [ ] Setup master password in password manager

## Setup Steps
1. Initialize vault: `ak init`
2. Import shared credentials: `ak import team-credentials.akb`
3. Add personal credentials
4. Setup backup automation
5. Test access to all services

## Team Credentials
- Staging database: `staging-db-password`
- Staging API: `staging-api-key`
- Development AWS: `dev-aws-key`

## Personal Credentials to Add
- GitHub personal token
- Personal AWS keys (if needed)
- Any other personal API keys

## Support
- Questions: #dev-tools Slack channel
- Issues: File ticket in Jira
```

---

## Advanced Scenarios

### Scenario 20: Automated Secret Rotation

**Context:** Implement automated 90-day secret rotation policy.

**Rotation Script:**
```bash
#!/bin/bash
# auto-rotate-secrets.sh

# Secrets to rotate
SECRETS=("github-token" "aws-key" "database-password")

# Rotation interval (90 days)
ROTATION_DAYS=90

for secret in "${SECRETS[@]}"; do
  # Check last rotation date (future feature)
  # last_rotation=$(ak show "$secret" --metadata | jq -r '.updated_at')

  # For now, rotate all
  echo "=== Rotating $secret ==="

  # 1. Generate new credential at provider
  case "$secret" in
    "github-token")
      # Use GitHub API to create new token
      new_token=$(gh api /user/tokens -f note="Auto-rotated $(date +%Y-%m-%d)" | jq -r '.token')
      ;;
    "aws-key")
      # Use AWS CLI to create new access key
      new_key=$(aws iam create-access-key --user-name myuser | jq -r '.AccessKey.AccessKeyId')
      ;;
    "database-password")
      # Generate secure random password
      new_password=$(openssl rand -base64 32)
      # Update at database
      mysql -u root -p -e "ALTER USER 'app'@'localhost' IDENTIFIED BY '$new_password';"
      ;;
  esac

  # 2. Update in vault
  echo -e "$MASTER_PASSWORD\n$new_value" | ak update "$secret"

  # 3. Test new credential
  ak exec --env TEST_KEY="$secret" -- ./test-credential.sh

  if [ $? -eq 0 ]; then
    echo "✓ $secret rotated successfully"

    # 4. Revoke old credential at provider
    # (implementation depends on provider)
  else
    echo "✗ $secret rotation FAILED - rolling back"
    # Rollback logic here
  fi
done

# 5. Export updated vault
ak export "*" "vault-rotated-$(date +%Y%m%d).akb"

# 6. Notify team
echo "Secret rotation complete. New vault exported."
```

**Schedule with cron:**
```bash
# Run every 90 days at 2 AM
0 2 */90 * * /home/user/scripts/auto-rotate-secrets.sh
```

---

## Summary

This guide covers 20 real-world scenarios for using AiKey CLI (`aikey` / `ak`):

**Individual Use:**
- Daily development workflows
- Project switching
- Machine migration

**Team Collaboration:**
- Sharing credentials
- Rotating shared secrets
- Onboarding new members

**DevOps:**
- CI/CD integration
- Docker containers
- Kubernetes deployments

**Security:**
- Audit trails
- Incident response
- Penetration testing

**Operations:**
- Multi-environment management
- Emergency recovery
- Automated rotation

Each scenario includes:
- ✅ Context and use case
- ✅ Step-by-step instructions
- ✅ Code examples
- ✅ Best practices
- ✅ Security considerations

---

**Next Steps:**
1. Choose scenarios relevant to your workflow
2. Adapt examples to your environment
3. Implement backup automation
4. Document your team's procedures
5. Train team members on best practices

**Need Help?**
- Documentation: `USER_MANUAL.md`
- Issues: https://github.com/AiKey-Founder/aikey-labs/issues
- Community: https://github.com/AiKey-Founder/aikey-labs/discussions
