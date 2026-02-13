#!/bin/bash
set -e

echo "=========================================="
echo "AiKey v0.0.1-alpha - Version Reset Script"
echo "=========================================="
echo ""
echo "WARNING: This will:"
echo "  1. Delete all Git history"
echo "  2. Create a fresh repository"
echo "  3. Force push to remote (overwriting main branch)"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Step 1: Configuring Git identity..."
git config user.name "AiKey Founder"
git config user.email "aikeyfounder@gmail.com"

echo "Step 2: Removing old Git history..."
rm -rf .git

echo "Step 3: Initializing fresh repository..."
git init
git branch -M main

echo "Step 4: Staging all files..."
git add .

echo "Step 5: Creating initial commit..."
git commit -m "feat: official release v0.0.1-alpha

- Secure storage with AES-256-GCM encryption
- Argon2id key derivation with password verification
- Environment injection with signal propagation
- Magic Add with smart secret detection
- Comprehensive integration test suite (8 tests)
- Production-ready error handling and security

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"

echo "Step 6: Adding remote origin..."
git remote add origin https://github.com/AiKey-Labs/aikey-labs.git

echo ""
echo "=========================================="
echo "Ready to force push!"
echo "=========================================="
echo ""
echo "Run the following command to force push:"
echo ""
echo "  git push -f origin main"
echo ""
echo "This will PERMANENTLY overwrite the remote repository history."
read -p "Push now? (yes/no): " push_confirm

if [ "$push_confirm" = "yes" ]; then
    echo ""
    echo "Pushing to remote..."
    git push -f origin main
    echo ""
    echo "✓ Successfully pushed v0.0.1-alpha to GitHub!"
    echo ""
    echo "Repository: https://github.com/AiKey-Labs/aikey-labs"
else
    echo ""
    echo "Skipped push. Run manually when ready:"
    echo "  git push -f origin main"
fi

echo ""
echo "Done!"
