#!/bin/bash

# Script: GitHub App Authentication and Repository Clone
# Description: Authenticates with GitHub App and clones a repository
# Author: Obiajulu Ezike <de-marauder>
# Last Modified: 2025-03-23

###################
# Configuration  #
###################

# Exit on any error, undefined variable, or pipe failure
set -o errexit
set -o nounset
set -o pipefail

# Enable debug mode if DEBUG environment variable is set
[[ "${DEBUG:-false}" == "true" ]] && set -x

###################
# Constants      #
###################

readonly GITHUB_APP_ID="${GITHUB_APP_ID:-1188563}"
readonly GITHUB_ORG="${GITHUB_ORG:-de-marauder}"
readonly GITHUB_REPO="${GITHUB_REPO:-test-repo}"
readonly REGION="${AWS_REGION:-us-east-1}"
readonly TEMP_KEY_PATH="/tmp/github-app-${RANDOM}.pem"
readonly LOG_FILE="/var/log/github-app-auth.log"
readonly SECRET_NAME="github-app-private-key"

###################
# Functions      #
###################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

cleanup() {
    local exit_code=$?
    log "INFO" "Cleaning up temporary files..."
    
    # Securely remove the private key file if it exists
    if [[ -f "$TEMP_KEY_PATH" ]]; then
        shred -u "$TEMP_KEY_PATH"
    fi
    
    # Log script completion status
    if [[ $exit_code -eq 0 ]]; then
        log "INFO" "Script completed successfully"
    else
        log "ERROR" "Script failed with exit code $exit_code"
    fi
}

check_dependencies() {
    local deps=("aws" "jq" "curl" "openssl" "git")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR" "Required dependency not found: $dep"
            exit 1
        fi
    done
}

validate_inputs() {
    local errors=0

    if [[ ! "$GITHUB_APP_ID" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Invalid GitHub App ID format"
        ((errors++))
    fi

    if [[ ! "$GITHUB_ORG" =~ ^[a-zA-Z0-9-]+$ ]]; then
        log "ERROR" "Invalid GitHub organization name format"
        ((errors++))
    fi

    if [[ ! "$GITHUB_REPO" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        log "ERROR" "Invalid GitHub repository name format"
        ((errors++))
    fi

    if ((errors > 0)); then
        return 1
    fi
}

get_private_key() {
    local max_retries=3
    local retry_count=0
    local wait_time=5

    while ((retry_count < max_retries)); do
        if PRIVATE_KEY=$(aws secretsmanager get-secret-value \
            --secret-id "$SECRET_NAME" \
            --region "$REGION" \
            --query SecretString \
            --output text 2>/dev/null); then
            echo "$PRIVATE_KEY" > "$TEMP_KEY_PATH"
            chmod 600 "$TEMP_KEY_PATH"
            return 0
        fi

        log "WARN" "Failed to fetch private key, attempt $((retry_count + 1))/$max_retries"
        ((retry_count++))
        sleep "$wait_time"
    done

    log "ERROR" "Failed to fetch private key after $max_retries attempts"
    return 1
}

generate_jwt() {
    local now exp jwt signature
    now=$(date +%s)
    exp=$((now + 540)) # 9 minutes from now

    jwt=$(jq -n --arg now "$now" --arg exp "$exp" --arg iss "$GITHUB_APP_ID" \
        '{
            alg: "RS256",
            typ: "JWT"
        }' | openssl enc -base64 -A | tr -d '=' | tr '/+' '_-' ).$(jq -n --arg now "$now" --arg exp "$exp" --arg iss "$GITHUB_APP_ID" \
        '{
            iat: ($now | tonumber),
            exp: ($exp | tonumber),
            iss: ($iss | tonumber)
        }' | openssl enc -base64 -A | tr -d '=' | tr '/+' '_-' )

    signature=$(echo -n "$jwt" | \
        openssl dgst -sha256 -sign "$TEMP_KEY_PATH" | \
        openssl enc -base64 -A | tr -d '=' | tr '/+' '_-')

    echo "${jwt}.${signature}"
}

get_installation_id() {
    local jwt="$1"
    local installation_id

    installation_id=$(curl -s -f -H "Authorization: Bearer $jwt" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/app/installations" | \
        jq -r ".[] | select(.account.login==\"$GITHUB_ORG\") | .id")

    if [[ -z "$installation_id" ]]; then
        log "ERROR" "Failed to get installation ID for organization $GITHUB_ORG"
        return 1
    fi

    echo "$installation_id"
}

get_access_token() {
    local jwt="$1"
    local installation_id="$2"
    local access_token

    access_token=$(curl -s -f -X POST \
        -H "Authorization: Bearer $jwt" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/app/installations/$installation_id/access_tokens" | \
        jq -r '.token')

    if [[ -z "$access_token" ]]; then
        log "ERROR" "Failed to get access token"
        return 1
    fi

    echo "$access_token"
}

clone_repository() {
    local access_token="$1"
    local clone_url="https://x-access-token:${access_token}@github.com/${GITHUB_ORG}/${GITHUB_REPO}.git"

    if ! git clone "$clone_url"; then
        log "ERROR" "Failed to clone repository"
        return 1
    fi
}

###################
# Main Script    #
###################

main() {
    local jwt installation_id access_token

    # Setup cleanup trap
    trap cleanup EXIT

    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"

    log "INFO" "Starting GitHub App authentication process"

    # Check dependencies
    check_dependencies

    # Validate inputs
    if ! validate_inputs; then
        log "ERROR" "Input validation failed"
        exit 1
    fi

    # Get private key
    if ! get_private_key; then
        exit 1
    fi

    # Generate JWT
    log "INFO" "Generating JWT"
    jwt=$(generate_jwt)

    # Get installation ID
    log "INFO" "Getting installation ID"
    installation_id=$(get_installation_id "$jwt")

    # Get access token
    log "INFO" "Getting access token"
    access_token=$(get_access_token "$jwt" "$installation_id")

    # Clone repository
    log "INFO" "Cloning repository"
    clone_repository "$access_token"

    log "INFO" "Repository cloned successfully"
}

# Execute main function
main