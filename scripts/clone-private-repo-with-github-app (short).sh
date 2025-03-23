#!/bin/bash

set -euo pipefail

# Constants
readonly GITHUB_APP_ID="${GITHUB_APP_ID:-1188563}"
readonly GITHUB_ORG="${GITHUB_ORG:-de-marauder}"
readonly GITHUB_REPO="${GITHUB_REPO:-test-repo}"
readonly SECRET_NAME="github-app-private-key"
readonly TEMP_KEY_PATH="/tmp/github-app-${RANDOM}.pem"

cleanup() {
    # Securely remove the private key file
    if [[ -f "$TEMP_KEY_PATH" ]]; then
        shred -u "$TEMP_KEY_PATH"
    fi
}

trap cleanup EXIT

# Get private key from Secrets Manager
aws secretsmanager get-secret-value \
    --secret-id "$SECRET_NAME" \
    --query SecretString \
    --output text > "$TEMP_KEY_PATH"

chmod 600 "$TEMP_KEY_PATH"

# Generate JWT
NOW=$(date +%s)
EXP=$((NOW + 540))

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
    openssl dgst -sha256 -sign "$TEMP_KEY_PATH" | \
    openssl enc -base64 -A | tr -d '=' | tr '/+' '_-')

JWT="$JWT.$SIGNATURE"

# Get installation ID
INSTALLATION_ID=$(curl -sS -H "Authorization: Bearer $JWT" \
    -H "Accept: application/vnd.github+json" \
    https://api.github.com/app/installations | \
    jq -r ".[] | select(.account.login==\"$GITHUB_ORG\") | .id")

# Get installation token
ACCESS_TOKEN=$(curl -sS -X POST \
    -H "Authorization: Bearer $JWT" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" | \
    jq -r '.token')

# Clone repository
git clone "https://x-access-token:$ACCESS_TOKEN@github.com/$GITHUB_ORG/$GITHUB_REPO.git" -q