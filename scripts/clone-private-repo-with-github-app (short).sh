#!/bin/bash

set -e

GITHUB_APP_ID=1188563
GITHUB_ORG=de-marauder
GITHUB_REPO=test-repo
REGION=us-east-1

# 1. Fetch GitHub App private key from AWS Secrets Manager
PRIVATE_KEY=$(aws secretsmanager get-secret-value \
  --secret-id github-app-private-key \
  --region $REGION \
  --query SecretString \
  --output text)

# 2. Save private key locally temporarily
echo '$PRIVATE_KEY > /tmp/github-app.pem'

# 3. Generate JWT
NOW=$(date +%s)
EXP=$((NOW + 540)) # 9 minutes from now

JWT=$(jq -n --arg now "$NOW" --arg exp "$EXP" --arg iss "$GITHUB_APP_ID" \
  '{
    alg: "RS256",
    typ: "JWT"
  }' | openssl enc -base64 -A | tr -d '=' | tr '/+' '_-' ).$(jq -n --arg now "$NOW" --arg exp "$EXP" --arg iss "$GITHUB_APP_ID" \
  '{
    iat: ($now | tonumber),
    exp: ($exp | tonumber),
    iss: ($iss | tonumber)
  }' | openssl enc -base64 -A | tr -d '=' | tr '/+' '_-' )

SIGNATURE=$(echo -n "$JWT" | \
  openssl dgst -sha256 -sign /tmp/github-app.pem | \
  openssl enc -base64 -A | tr -d '=' | tr '/+' '_-')

JWT="$JWT.$SIGNATURE"

# 4. Get installation ID
INSTALLATION_ID=$(curl -s -H "Authorization: Bearer $JWT" -H "Accept: application/vnd.github+json" \
  https://api.github.com/app/installations | jq -r ".[] | select(.account.login==\"$GITHUB_ORG\") | .id")

# 5. Get Installation Access Token
ACCESS_TOKEN=$(curl -s -X POST \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens | jq -r '.token')

# 6. Git clone with token
git clone https://x-access-token:$ACCESS_TOKEN@github.com/$GITHUB_ORG/$GITHUB_REPO.git

# 7. Cleanup
rm /tmp/github-app.pem