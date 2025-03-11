#!/usr/bin/env bash
#
# Octopus Deploy Worker Sharing Script
#
# This script automates the process of registering a worker in one Octopus Deploy space
# and sharing it with all other spaces on the instance.
#

# Author: Obiajulu Ezike (de-marauder)

set -o errexit  # Exit on error
set -o nounset  # Exit on unset variables
set -o pipefail # Exit on pipe failures

# Required variables
export OCTOPUS_URL="https://<your-url>.octopus.app"
export API_KEY="API-xxxx"
export ENV=''

# Optional variables with defaults
export WORKER_POOL_NAME="Shared Worker Pool"
export MAX_WAIT_TIME=300
export LOG_LEVEL=INFO
export LOG_FILE=/var/log/octopus-worker-sharing.log

# Configuration with defaults
: "${OCTOPUS_URL:?Environment variable OCTOPUS_URL must be set}"
: "${API_KEY:?Environment variable API_KEY must be set}"
: "${WORKER_POOL_NAME:=Shared Worker Pool <$ENV>}"
: "${MAX_WAIT_TIME:=300}" # 5 minutes timeout in seconds
: "${LOG_LEVEL:=INFO}"    # Options: DEBUG, INFO, WARN, ERROR
: "${LOG_FILE:=/var/log/octopus-worker-sharing.log}"
: "${HOSTNAME:=$(hostname) <$ENV>}"
: "${TENTACLE_CONFIG_PATH:=/etc/octopus/default/tentacle-default.config}"
: "${TENTACLE_APPLICATION_PATH:=/home/Octopus/Applications/}"
: "${TENTACLE_COMMS_PORT:=10943}"

# Ensure dependencies are installed
REQUIRED_TOOLS=("curl" "jq" "sudo")

# Initialize log file if it doesn't exist
if [[ ! -f "$LOG_FILE" && -w "$(dirname "$LOG_FILE")" ]]; then
    touch "$LOG_FILE" 2>/dev/null || true
fi

# Set log file permissions if we can
if [[ -f "$LOG_FILE" && -w "$LOG_FILE" ]]; then
    chmod 640 "$LOG_FILE" 2>/dev/null || true
fi

#
# Logging functions
#
function log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Log levels priority: DEBUG < INFO < WARN < ERROR
    case "$LOG_LEVEL" in
    DEBUG) ;;
    INFO)
        [[ "$level" == "DEBUG" ]] && return 0
        ;;
    WARN)
        [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return 0
        ;;
    ERROR)
        [[ "$level" != "ERROR" ]] && return 0
        ;;
    *)
        # Default to INFO
        [[ "$level" == "DEBUG" ]] && return 0
        ;;
    esac

    # Always show messages in console
    echo "[${timestamp}] [${level}] ${message}"

    # Write to log file if it exists and is writable
    if [[ -f "$LOG_FILE" && -w "$LOG_FILE" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >>"$LOG_FILE"
    fi
}

function log_debug() { log "DEBUG" "$1"; }
function log_info() { log "INFO" "$1"; }
function log_warn() { log "WARN" "$1"; }
function log_error() { log "ERROR" "$1"; }

#
# Error handling
#
function cleanup() {
    # Any cleanup needed before exit
    log_debug "Performing cleanup..."
}

function handle_error() {
    local exit_code="$?"
    local line_number="$1"
    log_error "Error occurred at line ${line_number}, exit code: ${exit_code}"
    cleanup
    exit "$exit_code"
}

# Set up error trapping
trap 'handle_error $LINENO' ERR

#
# Dependency checking
#
function check_dependencies() {
    local missing_tools=()

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_info "Installing missing tools: ${missing_tools[*]}"

        # Detect package manager
        if command -v apt >/dev/null; then
            sudo apt update -y && sudo apt install -y "${missing_tools[@]}"
        elif command -v apt-get >/dev/null; then
            sudo apt-get install -y "${missing_tools[@]}"
        else
            log_error "No supported package manager found. Please install missing tools manually: ${missing_tools[*]}"
            exit 1
        fi
    else
        log_info "All required tools are installed."
    fi
}

#
# Input validation
#
function validate_inputs() {
    # Validate URL format
    if [[ ! "$OCTOPUS_URL" =~ ^https?://[a-zA-Z0-9.-]+(\:[0-9]+)?(/.*)?$ ]]; then
        log_error "Invalid URL format: $OCTOPUS_URL"
        exit 1
    fi

    # Remove trailing slash from URL if present
    if [[ "$OCTOPUS_URL" == */ ]]; then
        OCTOPUS_URL="${OCTOPUS_URL%/}"
        log_debug "Removed trailing slash from URL: $OCTOPUS_URL"
    fi

    # Validate API key format (basic check)
    if [[ ! "$API_KEY" =~ ^API-[A-Za-z0-9]+$ ]]; then
        log_error "Invalid API key format. Should start with 'API-' followed by alphanumeric characters."
        exit 1
    fi

    # Validate numeric values
    if ! [[ "$MAX_WAIT_TIME" =~ ^[0-9]+$ ]]; then
        log_error "MAX_WAIT_TIME must be a positive integer."
        exit 1
    fi

    if ! [[ "$TENTACLE_COMMS_PORT" =~ ^[0-9]+$ ]]; then
        log_error "TENTACLE_COMMS_PORT must be a positive integer."
        exit 1
    fi
}

#
# API functions
#
function octopus_api() {
    local method="$1"
    local endpoint="$2"
    local data=""
    local response
    local http_code
    local api_url="${OCTOPUS_URL}/api/${endpoint}"
    local attempt=1
    local max_attempts=3
    local wait_time=5

    if [[ $# -ge 3 ]]; then # Check if at least 3 arguments are passed
        data="$3"           # Only assign if $3 exists
    fi
    while [[ $attempt -le $max_attempts ]]; do
        local res_file_path="/tmp/octopus_response.$$.$RANDOM"
        # log_info "Writing response to $res_file_path"
        if [[ -z "$data" ]]; then
            http_code=$(curl -s -o $res_file_path -w "%{http_code}" \
                -X "$method" \
                -H "X-Octopus-ApiKey: $API_KEY" \
                "$api_url")
            # log_debug "API Response: $http_code $res_file_path"
        else
            # log_debug "API Request: $method $api_url with data"
            http_code=$(curl -s -o $res_file_path -w "%{http_code}" \
                -X "$method" \
                -H "X-Octopus-ApiKey: $API_KEY" \
                -H "Content-Type: application/json" \
                -d "$data" \
                "$api_url")
            # log_debug "API Response with data: $http_code $res_file_path"
        fi

        if [[ ! -f $res_file_path ]]; then
            log_error "Failed to retrieve response file $res_file_path"
            return 1
        fi
        # cat $res_file_path
        response=$(<"$res_file_path")
        rm -f "$res_file_path"

        # Check for success
        if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            echo "$response"
            return 0
        fi

        # Handle rate limiting (429)
        if [[ "$http_code" -eq 429 ]]; then
            log_warn "Rate limited. Waiting before retry. Attempt $attempt of $max_attempts"
            sleep $((wait_time * attempt))
            attempt=$((attempt + 1))
            continue
        fi

        # Handle server errors (5xx)
        if [[ "$http_code" =~ ^5[0-9][0-9]$ ]]; then
            log_warn "Server error ($http_code). Waiting before retry. Attempt $attempt of $max_attempts"
            sleep $((wait_time * attempt))
            attempt=$((attempt + 1))
            continue
        fi

        # Client errors (4xx) other than rate limiting
        log_error "API request failed with HTTP code $http_code"
        log_error "Response: $response"
        return 1
    done

    log_error "API request failed after $max_attempts attempts"
    log_error "Last response: $response"
    return 1
}

function get_all_items() {
    local endpoint="$1"
    local items=()
    local skip=0
    local result
    local result_items
    local more_items=true
    local page=1

    log_debug "Getting all items from $endpoint"

    while $more_items; do
        # Check if endpoint already has query parameters
        if [[ "$endpoint" == *"?"* ]]; then
            result=$(octopus_api "GET" "$endpoint&skip=$skip")
        else
            result=$(octopus_api "GET" "$endpoint?skip=$skip")
        fi

        if [[ -z "$result" ]]; then
            log_error "Failed to get items from $endpoint"
            return 1
        fi

        result_items=$(echo "$result" | jq -r '.Items')

        if [[ "$result_items" == "null" ]]; then
            # Not a collection, return the whole result
            echo "$result"
            return 0
        fi

        # Get the items from this page
        local page_items
        page_items=$(echo "$result" | jq -r '.Items')
        local page_count
        page_count=$(echo "$page_items" | jq -r 'length')

        log_debug "Retrieved page $page with $page_count items"

        # Combine with existing items
        if [[ -z "${items[*]}" ]]; then
            items=$page_items
        else
            items=$(echo "$items $page_items" | jq -s 'add')
        fi

        # Check if we got a full page of results
        local items_count
        items_count=$(echo "$result" | jq -r '.Items | length')
        local items_per_page
        items_per_page=$(echo "$result" | jq -r '.ItemsPerPage')

        if [[ "$items_count" -lt "$items_per_page" ]]; then
            more_items=false
        else
            skip=$((skip + items_per_page))
            page=$((page + 1))
        fi
    done

    local total_count
    total_count=$(echo "$items" | jq -r 'length')
    log_debug "Retrieved a total of $total_count items from $endpoint"

    # Create a result object with the combined items
    echo "{\"Items\": $items}"
}

#
# Tentacle/worker management functions
#
function install_tentacle() {
    log_info "Installing Tentacle..."

    # Check if we can detect the OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release

        if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            log_info "Detected $ID distribution"

            # Add Octopus Deploy repository
            if ! sudo apt-key adv --fetch-keys "https://apt.octopus.com/public.key"; then
                log_error "Failed to fetch Octopus Deploy APT key"
                return 1
            fi

            if ! sudo add-apt-repository -y "deb https://apt.octopus.com/ focal main"; then
                log_error "Failed to add Octopus Deploy repository"
                return 1
            fi

            # Update and install
            if ! sudo apt-get update -y; then
                log_error "Failed to update package lists"
                return 1
            fi

            if ! sudo apt-get install tentacle -y; then
                log_error "Failed to install Tentacle"
                return 1
            fi
        else
            log_error "Unsupported Linux distribution: $ID"
            log_error "Please install Tentacle manually"
            return 1
        fi
    else
        log_error "Could not detect OS distribution"
        log_error "Please install Tentacle manually"
        return 1
    fi

    log_info "Tentacle installed successfully"
    return 0
}

function configure_tentacle() {
    log_info "Configuring Tentacle..."

    if ! sudo /opt/octopus/tentacle/Tentacle create-instance \
        --config "$TENTACLE_CONFIG_PATH" \
        --instance "$HOSTNAME"; then
        log_error "Failed to create Tentacle instance"
        return 1
    fi

    if ! sudo /opt/octopus/tentacle/Tentacle new-certificate --if-blank; then
        log_error "Failed to create Tentacle certificate"
        return 1
    fi

    if ! sudo /opt/octopus/tentacle/Tentacle configure \
        --noListen True \
        --reset-trust \
        --app "$TENTACLE_APPLICATION_PATH"; then
        log_error "Failed to configure Tentacle"
        return 1
    fi

    if ! sudo /opt/octopus/tentacle/Tentacle service --install --start; then
        log_error "Failed to install and start Tentacle service"
        return 1
    fi

    log_info "Tentacle configured successfully"
    return 0
}

function get_worker_id_by_hostname() {
    local space_id="$1"
    local pool_id="$2"
    local workers
    local worker_id

    workers=$(octopus_api "GET" "$space_id/workerpools/$pool_id/workers")
    # check for workers with name as HOSTNAME
    worker_id=$(echo "$workers" | jq -r '.Items[] | select(.Name == "'"$HOSTNAME"'") |.Id')

    echo "$worker_id"
}

function register_worker() {
    local space_name="$1"
    local spaces
    local space_id
    local worker_pools
    local pool_id
    local workers
    local worker_id

    log_info "Checking if worker $HOSTNAME is registered in space '$space_name'..."

    # Get spaces and find the one matching space_name
    spaces=$(octopus_api "GET" "spaces")
    if [[ -z "$spaces" ]]; then
        log_error "Failed to get spaces"
        return 1
    fi
    space_id=$(echo "$spaces" | jq -r '.Items[] | select(.Name == "'"$space_name"'") |.Id')
    log_info "Got space_id=$space_id"
    if [[ -z "$space_id" ]]; then
        log_error "Space '$space_name' not found"
        return 1
    fi
    workerpools=$(octopus_api "GET" "$space_id/workerpools")
    if [[ -z "$workerpools" ]]; then
        log_error "Failed to get worker pools"
        return 1
    fi
    pool_id=$(echo "$workerpools" | jq -r '.Items[] | select(.Name == "'"$WORKER_POOL_NAME"'") |.Id')
    if [[ -z "$pool_id" ]]; then
        log_error "Worker pool '$WORKER_POOL_NAME' not found in space '$space_name'"
        return 1
    fi
    worker_id=$(get_worker_id_by_hostname $space_id $pool_id)

    if [[ -z "$worker_id" ]]; then
        log_info "Worker $HOSTNAME is not registered. Registering..."
        log_info "Registering worker $HOSTNAME in space '$space_name'..."

        if ! sudo /opt/octopus/tentacle/Tentacle register-worker \
            --server "$OCTOPUS_URL" \
            --apiKey "$API_KEY" \
            --name "$HOSTNAME" \
            --comms-style "TentacleActive" \
            --server-comms-port "$TENTACLE_COMMS_PORT" \
            --workerPool "$WORKER_POOL_NAME" \
            --policy "Default Machine Policy" \
            --space "$space_name"; then
            log_error "Failed to register worker"
            return 1
        fi

        if ! sudo /opt/octopus/tentacle/Tentacle service --restart; then
            log_error "Failed to restart Tentacle service"
            return 1
        fi

        log_info "Worker registered successfully"
        return 0
    else
        log_info "Worker $HOSTNAME is already registered in space '$space_name'"
        return 0
    fi

}

#
# Main functions
#
function wait_for_worker_health() {
    local space_id="$1"
    local pool_id="$2"
    local start_time
    local current_time
    local elapsed
    local worker_healthy=false
    local worker_id=""

    log_info "Waiting for worker to be healthy (up to $MAX_WAIT_TIME seconds)..."
    start_time=$(date +%s)

    while [[ "$worker_healthy" == "false" ]]; do
        local workers
        workers=$(octopus_api "GET" "$space_id/workerpools/$pool_id/workers")

        if [[ -z "$workers" ]]; then
            log_error "Failed to get workers $workers"
            return 1
        fi

        local worker
        worker=$(echo "$workers" | jq -r '.Items[] | select(.Name=="'"$HOSTNAME"'")')

        if [[ -n "$worker" && "$worker" != "null" ]]; then
            worker_id=$(echo "$worker" | jq -r '.Id')
            local health_status
            health_status=$(echo "$worker" | jq -r '.HealthStatus')

            if [[ "$health_status" == "Healthy" ]]; then
                worker_healthy=true
                log_info "Worker is now healthy!"
            else
                log_debug "Worker health status: $health_status. Waiting..."
            fi
        else
            log_debug "Worker not found yet. Waiting..."
        fi

        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        if [[ $elapsed -gt $MAX_WAIT_TIME ]]; then
            log_error "Timeout waiting for worker to become healthy!"
            return 1
        fi

        if [[ "$worker_healthy" == "false" ]]; then
            sleep 15
            log_info "Retrying: Waiting for worker to be healthy..."
        fi
    done

}

function get_or_create_worker_pool() {
    local space_id="$1"
    local space_name="$2"

    local worker_pools
    worker_pools=$(get_all_items "$space_id/workerpools")

    if [[ -z "$worker_pools" ]]; then
        log_error "Failed to get worker pools for space $space_name"
        return 1
    fi

    local worker_pool
    worker_pool=$(echo "$worker_pools" | jq -r '.Items[] | select(.Name=="'"$WORKER_POOL_NAME"'")')

    if [[ -z "$worker_pool" || "$worker_pool" == "null" ]]; then
        # log_info "Creating worker pool '$WORKER_POOL_NAME' in space '$space_name'..."

        local worker_pool_data
        worker_pool_data='{
            "Name": "'"$WORKER_POOL_NAME"'",
            "WorkerPoolType": "StaticWorkerPool",
            "Description": "Shared worker pool across all spaces - Managed by automation script"
        }'

        worker_pool=$(octopus_api "POST" "$space_id/workerpools" "$worker_pool_data")

        if [[ -z "$worker_pool" ]]; then
            log_error "Failed to create worker pool in space $space_name"
            return 1
        fi

        # log_info "Worker pool created successfully"
        # else
        # log_info "Worker pool '$WORKER_POOL_NAME' already exists in space '$space_name'"
    fi

    local worker_pool_id
    worker_pool_id=$(echo "$worker_pool" | jq -r '.Id')

    echo "$worker_pool_id"
}

function get_default_machine_policy() {
    local space_id="$1"
    local space_name="$2"

    log_debug "Getting default machine policy for space '$space_name'..."

    local machine_policies
    machine_policies=$(get_all_items "$space_id/machinepolicies")

    if [[ -z "$machine_policies" ]]; then
        log_error "Failed to get machine policies for space $space_name"
        return 1
    fi

    local default_policy
    default_policy=$(echo "$machine_policies" | jq -r '.Items[] | select(.Name=="Default Machine Policy")')

    if [[ -z "$default_policy" || "$default_policy" == "null" ]]; then
        log_error "Default Machine Policy not found in space $space_name"
        return 1
    fi

    local policy_id
    policy_id=$(echo "$default_policy" | jq -r '.Id')

    echo "$policy_id"
}

function add_worker_to_space() {
    local space_id="$1"
    local space_name="$2"
    local worker_details="$3"
    local policy_id="$4"
    local pool_id="$5"

    log_info "Adding worker to space '$space_name'..."

    # Check if worker already exists in this space
    local space_workers
    space_workers=$(get_all_items "$space_id/workers")

    if [[ -z "$space_workers" ]]; then
        log_error "Failed to get workers for space $space_name"
        return 1
    fi

    local existing_worker
    existing_worker=$(echo "$space_workers" | jq -r '.Items[] | select(.Name=="'"$HOSTNAME"'")')

    if [[ -z "$existing_worker" || "$existing_worker" == "null" ]]; then
        log_info "Creating worker '$HOSTNAME' in space '$space_name'..."

        # Create worker data
        local worker_data
        worker_data=$(echo "$worker_details" | jq '{
            Name: .Name,
            MachinePolicyId: "'"$policy_id"'",
            IsDisabled: .IsDisabled,
            HealthStatus: .HealthStatus,
            HasLatestCalamari: .HasLatestCalamari,
            IsInProcess: true,
            Endpoint: .Endpoint,
            WorkerPoolIds: ["'"$pool_id"'"]
        }')

        # Add worker to this space
        local add_result
        add_result=$(octopus_api "POST" "$space_id/workers" "$worker_data")

        if [[ -z "$add_result" ]]; then
            log_error "Failed to add worker to space $space_name"
            return 1
        elif [[ "$add_result" == *"error"* ]]; then
            log_error "Error adding worker to space $space_name:"
            log_error "$add_result"
            return 1
        else
            log_info "Successfully added worker to space '$space_name'"
        fi
    else
        log_info "Worker '$HOSTNAME' already exists in space '$space_name'"

        # Update worker to ensure it's in the correct worker pool
        local existing_worker_id
        existing_worker_id=$(echo "$existing_worker" | jq -r '.Id')
        local existing_worker_pools
        existing_worker_pools=$(echo "$existing_worker" | jq -r '.WorkerPoolIds')

        # Check if worker is already in the pool
        if [[ ! "$existing_worker_pools" == *"$pool_id"* ]]; then
            log_info "Adding worker '$HOSTNAME' to pool '$WORKER_POOL_NAME' in space '$space_name'..."

            # Get current worker pools and add the new one
            local updated_pools
            updated_pools=$(echo "$existing_worker_pools" | jq '. + ["'"$pool_id"'"]')

            # Create update data
            local update_data
            update_data=$(echo "$existing_worker" | jq '{
                Id: .Id,
                Name: .Name,
                MachinePolicyId: .MachinePolicyId,
                IsDisabled: .IsDisabled,
                WorkerPoolIds: '"$updated_pools"'
            }')

            # Update worker
            local update_result
            update_result=$(octopus_api "PUT" "$space_id/workers/$existing_worker_id" "$update_data")

            if [[ -z "$update_result" ]]; then
                log_error "Failed to update worker in space $space_name"
                return 1
            fi

            log_info "Worker updated successfully"
        else
            log_info "Worker '$HOSTNAME' is already in pool '$WORKER_POOL_NAME' in space '$space_name'"
        fi
    fi

    return 0
}

function main() {
    log_info "===== Starting Octopus Deploy Worker Sharing Process ====="
    log_info "Octopus URL: $OCTOPUS_URL"
    log_info "Worker Pool: $WORKER_POOL_NAME"
    log_info "Hostname: $HOSTNAME"

    # Initial checks
    check_dependencies
    validate_inputs

    # Step 1: Get all spaces
    log_info "Getting all spaces..."
    local spaces_result
    spaces_result=$(get_all_items "spaces")

    if [[ -z "$spaces_result" ]]; then
        log_error "Failed to get spaces"
        exit 1
    fi

    local spaces
    spaces=$(echo "$spaces_result" | jq -r '.Items')
    local space_count
    space_count=$(echo "$spaces" | jq -r 'length')

    if [[ "$space_count" -eq 0 ]]; then
        log_error "No spaces found!"
        exit 1
    fi

    log_info "Found $space_count spaces"

    # Step 2: Get the first space as the initial space
    local initial_space_id
    initial_space_id=$(echo "$spaces" | jq -r '.[0].Id')
    local initial_space_name
    initial_space_name=$(echo "$spaces" | jq -r '.[0].Name')
    log_info "Using '$initial_space_name' (ID: $initial_space_id) as the initial space"

    # Step 3: Get or create worker pool in the initial space
    log_info "Checking if worker pool '$WORKER_POOL_NAME' exists in space '$initial_space_name'..."
    local worker_pool_id
    worker_pool_id=$(get_or_create_worker_pool "$initial_space_id" "$initial_space_name")

    if [[ -z "$worker_pool_id" ]]; then
        log_error "Failed to get or create worker pool"
        exit 1
    fi

    log_info "Worker pool ID: $worker_pool_id"

    # Step 4: Check if Tentacle is installed and configured
    if ! command -v /opt/octopus/tentacle/Tentacle &>/dev/null; then
        log_info "Tentacle not installed. Installing..."
        if ! install_tentacle; then
            log_error "Failed to install Tentacle"
            exit 1
        fi
    else
        log_info "Tentacle is already installed"
    fi

    # Configure tentacle if not already configured
    if [[ ! -f "$TENTACLE_CONFIG_PATH" ]]; then
        log_info "Configuring Tentacle..."
        if ! configure_tentacle; then
            log_error "Failed to configure Tentacle"
            exit 1
        fi
    else
        log_info "Tentacle is already configured"
    fi

    # Step 5: Register this machine as a worker in the initial space
    if ! register_worker "$initial_space_name"; then
        log_error "Failed to register worker"
        exit 1
    fi
    log_info "Tentacle is already registered"

    log_info "Step 6: Wait for worker to be healthy"
    # Step 6: Wait for worker to be healthy
    local worker_id

    log_info "Step 6: Wait for worker in $worker_pool_id to be healthy"
    if ! wait_for_worker_health "$initial_space_id" "$worker_pool_id"; then
        log_error "Failed to get healthy worker"
        exit 1
    fi

    worker_id=$(get_worker_id_by_hostname "$initial_space_id" "$worker_pool_id")
    log_info "Step 6: Worker $worker_id healthy"

    if [[ -z "$worker_id" ]]; then
        log_error "Failed to get healthy worker_id"
        exit 1
    fi

    log_info "Worker ID: $worker_id"

    log_info "Step 7: Get worker details for replication"
    log_info "Getting worker details for replication..."
    local worker_details
    worker_details=$(octopus_api "GET" "$initial_space_id/workers/$worker_id")

    if [[ -z "$worker_details" ]]; then
        log_error "Failed to get worker details"
        exit 1
    fi

    log_info "Step 8: Add worker to all other spaces"
    log_info "Adding worker to remaining spaces..."

    mapfile -t spaces_array < <(echo "$spaces" | jq -c '.[]')
    for space in "${spaces_array[@]}"; do
        local space_id
        space_id=$(echo "$space" | jq -r '.Id')
        local space_name
        space_name=$(echo "$space" | jq -r '.Name')
        log_info $space_id $space_name

        # Skip the initial space
        if [[ "$space_id" == "$initial_space_id" ]]; then
            continue
        fi

        log_info "Processing space: $space_name (ID: $space_id)"

        # Get or create worker pool in this space
        local space_pool_id
        space_pool_id=$(get_or_create_worker_pool "$space_id" "$space_name")

        if [[ -z "$space_pool_id" ]]; then
            log_error "Failed to get or create worker pool in space $space_name"
            continue
        fi

        # Get default machine policy for this space
        local space_policy_id
        space_policy_id=$(get_default_machine_policy "$space_id" "$space_name")

        if [[ -z "$space_policy_id" ]]; then
            log_error "Failed to get default machine policy in space $space_name"
            continue
        fi

        # Add worker to this space
        if ! add_worker_to_space "$space_id" "$space_name" "$worker_details" "$space_policy_id" "$space_pool_id"; then
            log_warn "Failed to add worker to space $space_name"
        fi
    done

    log_info "===== Worker sharing process complete! ====="
    log_info "Worker '$HOSTNAME' is now available in all spaces with the worker pool name: '$WORKER_POOL_NAME'"
    return 0
}

# Run main function
main
exit $?
