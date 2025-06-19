#!/bin/bash

# Aetheric Edge Cloud Bridge Configuration Script
# Enhanced version with certificate and username/password authentication support

set -e

# Configuration
MOSQUITTO_CONF_DIR="/etc/mosquitto/conf.d"
AETHERIC_USER_DIR="$HOME/.aetheric"
AETHERIC_CERTS_DIR="$AETHERIC_USER_DIR/certs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Usage function
usage() {
    echo "Aetheric Edge Cloud Bridge Configuration"
    echo ""
    echo "Usage: $0 <provider> <endpoint> [options]"
    echo ""
    echo "Providers:"
    echo "  aws      - Amazon Web Services IoT Core"
    echo "  azure    - Microsoft Azure IoT Hub"
    echo "  gcp      - Google Cloud IoT Core"
    echo "  custom   - Custom MQTT broker"
    echo ""
    echo "Authentication Options:"
    echo "  --cert-auth                   Use certificate authentication (default)"
    echo "  --cert-path <path>            Path to client certificate"
    echo "  --key-path <path>             Path to client private key"
    echo "  --ca-path <path>              Path to CA certificate"
    echo ""
    echo "  --username-auth               Use username/password authentication"
    echo "  --username <username>         MQTT username"
    echo "  --password <password>         MQTT password"
    echo ""
    echo "  --mixed-auth                  Use both certificate AND username/password"
    echo "  --custom-auth                 Use custom authentication (AWS Lambda/Azure)"
    echo "  --token <token>               Authentication token for custom auth"
    echo ""
    echo "Bridge Options:"
    echo "  --gateway-id <id>             Gateway ID (default: from config)"
    echo "  --port <port>                 MQTT port (default: 8883 for TLS, 1883 for plain)"
    echo "  --insecure                    Disable TLS verification"
    echo "  --qos <level>                 QoS level (0, 1, 2, default: 1)"
    echo ""
    echo "Examples:"
    echo "  # AWS IoT with certificates"
    echo "  $0 aws your-endpoint.iot.region.amazonaws.com --cert-auth"
    echo ""
    echo "  # AWS IoT with custom authentication (username/password)"
    echo "  $0 aws your-endpoint.iot.region.amazonaws.com --custom-auth --username device001 --password secret123 --port 443"
    echo ""
    echo "  # Azure IoT Hub with mixed authentication (cert + username)"
    echo "  $0 azure myhub.azure-devices.net --mixed-auth --username 'myhub.azure-devices.net/device001/?api-version=2021-04-12' --password 'SharedAccessSignature sr=...' --cert-path /path/to/cert.pem"
    echo ""
    echo "  # Custom broker with username/password only"
    echo "  $0 custom mqtt.example.com --username-auth --username myuser --password mypass"
    echo ""
    echo "  # Custom broker with certificate and username (mixed auth)"
    echo "  $0 custom secure-mqtt.example.com --mixed-auth --username myuser --password mypass --cert-path /path/to/cert.pem"
}

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ❌ $1${NC}"
}

# Get gateway ID from config
get_gateway_id() {
    if command -v aetheric &> /dev/null; then
        GATEWAY_ID=$(aetheric config get gateway.id 2>/dev/null || echo "aetheric-$(hostname)")
    else
        GATEWAY_ID="aetheric-$(hostname)"
    fi
    echo "$GATEWAY_ID"
}

# Validate certificate files
validate_cert_files() {
    local cert_path="$1"
    local key_path="$2"
    local ca_path="$3"
    
    if [[ -n "$cert_path" ]] && [[ ! -f "$cert_path" ]]; then
        log_error "Certificate file not found: $cert_path"
        return 1
    fi
    
    if [[ -n "$key_path" ]] && [[ ! -f "$key_path" ]]; then
        log_error "Private key file not found: $key_path"
        return 1
    fi
    
    if [[ -n "$ca_path" ]] && [[ ! -f "$ca_path" ]]; then
        log_error "CA certificate file not found: $ca_path"
        return 1
    fi
    
    return 0
}

# Create AWS IoT bridge configuration
create_aws_bridge() {
    local endpoint="$1"
    local gateway_id="$2"
    local auth_type="$3"
    local config_file="$MOSQUITTO_CONF_DIR/bridge-aws.conf"
    
    log "Creating AWS IoT Core bridge configuration..."
    
    cat > "$config_file" << EOF
# AWS IoT Core Bridge Configuration
# Generated on $(date)
connection aws-iot-bridge
address ${endpoint}:${PORT:-8883}

# Topic mapping
topic ae/+/health out 1 \$aws/things/${gateway_id}/
topic ae/+/telemetry out 1 \$aws/things/${gateway_id}/
topic ae/+/events out 1 \$aws/things/${gateway_id}/
topic \$aws/things/${gateway_id}/shadow/update/delta in 1 ae/${gateway_id}/cmd/
topic \$aws/things/${gateway_id}/jobs/+/get/accepted in 1 ae/${gateway_id}/jobs/

# Protocol settings
bridge_protocol_version mqttv311
bridge_insecure ${INSECURE:-false}
cleansession false
try_private false
start_type automatic
restart_timeout 30
keepalive_interval 60
max_inflight_messages 20

EOF

    # Add authentication based on type
    case "$auth_type" in
        "cert")
            cat >> "$config_file" << EOF
# Certificate authentication only
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
EOF
            ;;
        "username")
            cat >> "$config_file" << EOF
# Username/password authentication only (not recommended for AWS IoT)
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "mixed")
            cat >> "$config_file" << EOF
# Mixed authentication: Certificate + Username/Password
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "custom")
            # For AWS IoT custom auth, use port 443 and special configuration
            if [[ -n "$TOKEN" ]]; then
                cat >> "$config_file" << EOF
# Custom token-based authentication (AWS IoT Custom Authorizer)
remote_username ${USERNAME}?token=${TOKEN}
remote_password ${PASSWORD}
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
# Note: Custom auth requires port 443 and proper ALPN/SNI configuration
EOF
            else
                cat >> "$config_file" << EOF
# Custom username/password authentication (AWS IoT Custom Authorizer)
remote_username ${USERNAME}
remote_password ${PASSWORD}
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
# Note: Custom auth requires port 443 and proper ALPN/SNI configuration
EOF
            fi
            ;;
    esac
    
    log_success "AWS IoT bridge configuration created: $config_file"
}

# Create Azure IoT Hub bridge configuration
create_azure_bridge() {
    local endpoint="$1"
    local gateway_id="$2"
    local auth_type="$3"
    local config_file="$MOSQUITTO_CONF_DIR/bridge-azure.conf"
    
    log "Creating Azure IoT Hub bridge configuration..."
    
    cat > "$config_file" << EOF
# Azure IoT Hub Bridge Configuration
# Generated on $(date)
connection azure-iot-bridge
address ${endpoint}:${PORT:-8883}

# Topic mapping
topic ae/+/health out 1 devices/${gateway_id}/messages/events/
topic ae/+/telemetry out 1 devices/${gateway_id}/messages/events/
topic ae/+/events out 1 devices/${gateway_id}/messages/events/
topic devices/${gateway_id}/messages/devicebound/# in 1 ae/${gateway_id}/cmd/

# Protocol settings
bridge_protocol_version mqttv311
bridge_insecure ${INSECURE:-false}
cleansession false
try_private false
start_type automatic
restart_timeout 30
keepalive_interval 60
max_inflight_messages 20

EOF

    # Add authentication based on type
    case "$auth_type" in
        "cert")
            cat >> "$config_file" << EOF
# Certificate authentication only
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
username ${endpoint}/${gateway_id}/?api-version=2021-04-12
EOF
            ;;
        "username")
            cat >> "$config_file" << EOF
# Username/password authentication (SAS token or connection string)
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "mixed")
            cat >> "$config_file" << EOF
# Mixed authentication: Certificate + SAS token/connection string
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "custom")
            cat >> "$config_file" << EOF
# Custom authentication (Azure IoT custom method)
remote_username ${USERNAME}
remote_password ${PASSWORD}
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
EOF
            ;;
    esac
    
    log_success "Azure IoT Hub bridge configuration created: $config_file"
}

# Create Google Cloud IoT Core bridge configuration
create_gcp_bridge() {
    local endpoint="$1"
    local gateway_id="$2"
    local auth_type="$3"
    local config_file="$MOSQUITTO_CONF_DIR/bridge-gcp.conf"
    
    log "Creating Google Cloud IoT Core bridge configuration..."
    
    cat > "$config_file" << EOF
# Google Cloud IoT Core Bridge Configuration
# Generated on $(date)
connection gcp-iot-bridge
address ${endpoint}:${PORT:-8883}

# Topic mapping
topic ae/+/health out 1 /devices/${gateway_id}/events
topic ae/+/telemetry out 1 /devices/${gateway_id}/events
topic ae/+/events out 1 /devices/${gateway_id}/events
topic /devices/${gateway_id}/commands/# in 1 ae/${gateway_id}/cmd/

# Protocol settings
bridge_protocol_version mqttv311
bridge_insecure ${INSECURE:-false}
cleansession false
try_private false
start_type automatic
restart_timeout 30
keepalive_interval 60
max_inflight_messages 20

EOF

    # Add authentication based on type
    case "$auth_type" in
        "cert")
            cat >> "$config_file" << EOF
# Certificate authentication only
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
EOF
            ;;
        "username")
            cat >> "$config_file" << EOF
# Username/password authentication (JWT token)
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "mixed")
            cat >> "$config_file" << EOF
# Mixed authentication: Certificate + JWT token
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "custom")
            cat >> "$config_file" << EOF
# Custom authentication (GCP IoT custom method)
remote_username ${USERNAME}
remote_password ${PASSWORD}
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
EOF
            ;;
    esac
    
    log_success "Google Cloud IoT Core bridge configuration created: $config_file"
}

# Create custom MQTT broker bridge configuration
create_custom_bridge() {
    local endpoint="$1"
    local gateway_id="$2"
    local auth_type="$3"
    local config_file="$MOSQUITTO_CONF_DIR/bridge-custom.conf"
    
    log "Creating custom MQTT broker bridge configuration..."
    
    cat > "$config_file" << EOF
# Custom MQTT Broker Bridge Configuration
# Generated on $(date)
connection custom-mqtt-bridge
address ${endpoint}:${PORT:-1883}

# Topic mapping (customize as needed)
topic ae/+/+ out ${QOS:-1}
topic cmd/+/+ in ${QOS:-1} ae/${gateway_id}/cmd/
topic events/+/+ in ${QOS:-1} ae/${gateway_id}/events/

# Protocol settings
bridge_protocol_version mqttv311
bridge_insecure ${INSECURE:-false}
cleansession false
try_private false
start_type automatic
restart_timeout 30
keepalive_interval 60
max_inflight_messages 20

EOF

    # Add authentication based on type
    case "$auth_type" in
        "cert")
            cat >> "$config_file" << EOF
# Certificate authentication only
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
EOF
            ;;
        "username")
            cat >> "$config_file" << EOF
# Username/password authentication only
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "mixed")
            cat >> "$config_file" << EOF
# Mixed authentication: Certificate + Username/Password
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
bridge_certfile ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}
bridge_keyfile ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}
remote_username ${USERNAME}
remote_password ${PASSWORD}
EOF
            ;;
        "custom")
            cat >> "$config_file" << EOF
# Custom authentication method
remote_username ${USERNAME}
remote_password ${PASSWORD}
bridge_cafile ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}
EOF
            if [[ -n "$TOKEN" ]]; then
                cat >> "$config_file" << EOF
# Custom token in username field
# remote_username ${USERNAME}?token=${TOKEN}
EOF
            fi
            ;;
    esac
    
    log_success "Custom MQTT broker bridge configuration created: $config_file"
}

# Test bridge connection
test_bridge_connection() {
    local provider="$1"
    
    log "Testing bridge connection..."
    
    # Restart mosquitto to apply new configuration
    if systemctl restart mosquitto; then
        log_success "Mosquitto restarted successfully"
        
        # Wait a bit for connection to establish
        sleep 5
        
        # Check mosquitto logs for connection status
        if journalctl -u mosquitto --since "1 minute ago" | grep -q "Connection.*established\|Connected to"; then
            log_success "Bridge connection established successfully"
            return 0
        else
            log_warning "Bridge connection status unclear. Check logs: journalctl -u mosquitto -f"
            return 1
        fi
    else
        log_error "Failed to restart mosquitto"
        return 1
    fi
}

# Main function
main() {
    # Parse command line arguments
    if [[ $# -lt 2 ]]; then
        usage
        exit 1
    fi
    
    PROVIDER="$1"
    ENDPOINT="$2"
    shift 2
    
    # Default values
    AUTH_TYPE="cert"
    PORT=""
    INSECURE="false"
    QOS="1"
    USERNAME=""
    PASSWORD=""
    TOKEN=""
    CERT_PATH=""
    KEY_PATH=""
    CA_PATH=""
    GATEWAY_ID=""
    
    # Parse additional arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cert-auth)
                AUTH_TYPE="cert"
                shift
                ;;
            --username-auth)
                AUTH_TYPE="username"
                shift
                ;;
            --mixed-auth)
                AUTH_TYPE="mixed"
                shift
                ;;
            --custom-auth)
                AUTH_TYPE="custom"
                shift
                ;;
            --token)
                TOKEN="$2"
                shift 2
                ;;
            --username)
                USERNAME="$2"
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --cert-path)
                CERT_PATH="$2"
                shift 2
                ;;
            --key-path)
                KEY_PATH="$2"
                shift 2
                ;;
            --ca-path)
                CA_PATH="$2"
                shift 2
                ;;
            --gateway-id)
                GATEWAY_ID="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --insecure)
                INSECURE="true"
                shift
                ;;
            --qos)
                QOS="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate inputs
    if [[ -z "$PROVIDER" ]] || [[ -z "$ENDPOINT" ]]; then
        log_error "Provider and endpoint are required"
        usage
        exit 1
    fi
    
    # Get gateway ID if not provided
    if [[ -z "$GATEWAY_ID" ]]; then
        GATEWAY_ID=$(get_gateway_id)
    fi
    
    # Validate authentication parameters
    case "$AUTH_TYPE" in
        "cert")
            if [[ -n "$CERT_PATH" ]] || [[ -n "$KEY_PATH" ]] || [[ -n "$CA_PATH" ]]; then
                validate_cert_files "$CERT_PATH" "$KEY_PATH" "$CA_PATH" || exit 1
            fi
            ;;
        "username")
            if [[ -z "$USERNAME" ]] || [[ -z "$PASSWORD" ]]; then
                log_error "Username and password are required for username authentication"
                exit 1
            fi
            ;;
        "mixed")
            # Validate both certificate and username/password
            if [[ -n "$CERT_PATH" ]] || [[ -n "$KEY_PATH" ]] || [[ -n "$CA_PATH" ]]; then
                validate_cert_files "$CERT_PATH" "$KEY_PATH" "$CA_PATH" || exit 1
            fi
            if [[ -z "$USERNAME" ]] || [[ -z "$PASSWORD" ]]; then
                log_error "Username and password are required for mixed authentication"
                exit 1
            fi
            ;;
        "custom")
            if [[ -z "$USERNAME" ]] || [[ -z "$PASSWORD" ]]; then
                log_error "Username and password are required for custom authentication"
                exit 1
            fi
            # Token is optional for custom auth
            ;;
    esac
    
    # Create mosquitto conf.d directory if it doesn't exist
    mkdir -p "$MOSQUITTO_CONF_DIR"
    
    # Export variables for use in configuration functions
    export PORT INSECURE QOS USERNAME PASSWORD CERT_PATH KEY_PATH CA_PATH
    
    log "Configuring bridge for $PROVIDER at $ENDPOINT"
    log "Gateway ID: $GATEWAY_ID"
    log "Authentication: $AUTH_TYPE"
    
    # Create bridge configuration based on provider
    case "$PROVIDER" in
        "aws")
            create_aws_bridge "$ENDPOINT" "$GATEWAY_ID" "$AUTH_TYPE"
            ;;
        "azure")
            create_azure_bridge "$ENDPOINT" "$GATEWAY_ID" "$AUTH_TYPE"
            ;;
        "gcp")
            create_gcp_bridge "$ENDPOINT" "$GATEWAY_ID" "$AUTH_TYPE"
            ;;
        "custom")
            create_custom_bridge "$ENDPOINT" "$GATEWAY_ID" "$AUTH_TYPE"
            ;;
        *)
            log_error "Unsupported provider: $PROVIDER"
            echo "Supported providers: aws, azure, gcp, custom"
            exit 1
            ;;
    esac
    
    # Test the bridge connection
    test_bridge_connection "$PROVIDER"
    
    echo ""
    log_success "Bridge configuration completed!"
    echo ""
    echo "📋 Configuration Summary:"
    echo "  Provider: $PROVIDER"
    echo "  Endpoint: $ENDPOINT"
    echo "  Gateway ID: $GATEWAY_ID"
    echo "  Authentication: $AUTH_TYPE"
    echo "  Configuration file: $MOSQUITTO_CONF_DIR/bridge-${PROVIDER}.conf"
    echo ""
    echo "🔧 Management Commands:"
    echo "  View logs: journalctl -u mosquitto -f"
    echo "  Restart bridge: sudo systemctl restart mosquitto"
    echo "  Test local MQTT: mosquitto_pub -h 127.0.0.1 -t ae/$GATEWAY_ID/test -m 'Hello Bridge'"
    echo ""
    
    # Show authentication-specific information
    case "$AUTH_TYPE" in
        "cert")
            echo "📜 Certificate Authentication:"
            echo "  Client cert: ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}"
            echo "  Private key: ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}"
            echo "  CA cert: ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}"
            echo ""
            echo "💡 Note: Ensure your certificates are valid and registered with $PROVIDER"
            ;;
        "username")
            echo "🔐 Username/Password Authentication:"
            echo "  Username: $USERNAME"
            echo "  Password: [REDACTED]"
            echo ""
            echo "💡 Note: Ensure your credentials are valid for $PROVIDER"
            ;;
        "mixed")
            echo "🔒 Mixed Authentication (Certificate + Username/Password):"
            echo "  Client cert: ${CERT_PATH:-$AETHERIC_CERTS_DIR/device-cert.pem}"
            echo "  Private key: ${KEY_PATH:-$AETHERIC_CERTS_DIR/device-key.pem}"
            echo "  CA cert: ${CA_PATH:-/etc/ssl/certs/ca-certificates.crt}"
            echo "  Username: $USERNAME"
            echo "  Password: [REDACTED]"
            echo ""
            echo "💡 Note: Both certificate and credentials must be valid for $PROVIDER"
            ;;
        "custom")
            echo "⚙️ Custom Authentication:"
            echo "  Username: $USERNAME"
            echo "  Password: [REDACTED]"
            if [[ -n "$TOKEN" ]]; then
                echo "  Token: [REDACTED]"
            fi
            echo ""
            echo "💡 Note: Custom authentication requires proper configuration on $PROVIDER"
            if [[ "$PROVIDER" == "aws" ]]; then
                echo "💡 AWS Note: Custom auth requires Lambda authorizer and port 443"
            fi
            ;;
    esac
}

# Check if running as root for mosquitto configuration
if [[ $EUID -ne 0 ]]; then
    echo "This script requires sudo privileges to configure mosquitto"
    echo "Please run: sudo $0 $*"
    exit 1
fi

# Run main function
main "$@"