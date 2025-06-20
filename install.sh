#!/bin/bash

# Aetheric Edge Installation Script
# Installs Aetheric Edge with local MQTT broker (Mosquitto) and cloud bridge configuration
# Similar architecture to thin-edge.io

set -e
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
AETHERIC_USER="aetheric"
AETHERIC_HOME="/opt/aetheric-edge"
AETHERIC_USER_DIR="$HOME/.aetheric"
AETHERIC_CONFIG_DIR="$AETHERIC_USER_DIR"
AETHERIC_DATA_DIR="$AETHERIC_USER_DIR/data"
AETHERIC_LOG_DIR="$AETHERIC_USER_DIR/logs"
AETHERIC_CERTS_DIR="$AETHERIC_USER_DIR/certs"
MOSQUITTO_CONFIG_DIR="/etc/mosquitto"
MOSQUITTO_DATA_DIR="/var/lib/mosquitto"
SYSTEMD_DIR="/etc/systemd/system"

# GitHub release settings (adjust these for your actual release)
GITHUB_REPO="your-org/aetheric-edge"  # Replace with actual repo
VERSION="latest"  # or specific version like "v1.0.0"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    log "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    log "Detected OS: $OS $VER"
    
    # Set package manager based on OS
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt update"
        PKG_INSTALL="apt install -y"
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        PKG_MANAGER="yum"
        PKG_UPDATE="yum update -y"
        PKG_INSTALL="yum install -y"
        if command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf update -y"
            PKG_INSTALL="dnf install -y"
        fi
    else
        log_error "Unsupported OS: $OS"
        exit 1
    fi
}

# Create aetheric user
create_user() {
    log "Creating aetheric user..."
    
    if ! id "$AETHERIC_USER" &>/dev/null; then
        useradd --system --home-dir "$AETHERIC_HOME" --create-home --shell /bin/false "$AETHERIC_USER"
        log_success "Created user: $AETHERIC_USER"
    else
        log_warning "User $AETHERIC_USER already exists"
    fi
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    # Get the actual user who invoked sudo
    ACTUAL_USER="${SUDO_USER:-$USER}"
    ACTUAL_HOME=$(eval echo "~$ACTUAL_USER")
    AETHERIC_USER_DIR="$ACTUAL_HOME/.aetheric"
    
    # Update paths with actual user directory
    AETHERIC_CONFIG_DIR="$AETHERIC_USER_DIR"
    AETHERIC_DATA_DIR="$AETHERIC_USER_DIR/data"
    AETHERIC_LOG_DIR="$AETHERIC_USER_DIR/logs"
    AETHERIC_CERTS_DIR="$AETHERIC_USER_DIR/certs"
    
    # Create main directories
    mkdir -p "$AETHERIC_HOME"/{bin,lib,plugins,temp}
    mkdir -p "$AETHERIC_USER_DIR"
    mkdir -p "$AETHERIC_DATA_DIR"/{mqtt,logs,plugins}
    mkdir -p "$AETHERIC_LOG_DIR"
    mkdir -p "$AETHERIC_CERTS_DIR"
    
    # Set ownership for system directories
    chown -R "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME"
    
    # Set ownership for user directories to actual user
    chown -R "$ACTUAL_USER:$ACTUAL_USER" "$AETHERIC_USER_DIR"
    
    # Set permissions
    chmod 755 "$AETHERIC_HOME"
    chmod 750 "$AETHERIC_USER_DIR"
    chmod 750 "$AETHERIC_CERTS_DIR"
    chmod 755 "$AETHERIC_DATA_DIR"
    chmod 755 "$AETHERIC_LOG_DIR"
    
    # Export variables for use in other functions
    export AETHERIC_USER_DIR AETHERIC_CONFIG_DIR AETHERIC_DATA_DIR AETHERIC_LOG_DIR AETHERIC_CERTS_DIR ACTUAL_USER
    
    log_success "Directory structure created in $AETHERIC_USER_DIR"
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    $PKG_UPDATE
    
    # Install required packages
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $PKG_INSTALL curl wget jq mosquitto mosquitto-clients systemd openssl ca-certificates
    elif [[ "$PKG_MANAGER" == "yum" ]] || [[ "$PKG_MANAGER" == "dnf" ]]; then
        $PKG_INSTALL curl wget jq mosquitto systemd openssl ca-certificates
    fi
    
    log_success "System dependencies installed"
}

# Download and install Aetheric Edge binaries
install_binaries() {
    log "Installing Aetheric Edge binaries..."
    
    # For now, we'll build from source since we don't have GitHub releases yet
    # In production, this would download pre-built binaries from GitHub releases
    
    if [[ -f "target/release/aetheric-agent" ]] && [[ -f "target/release/aetheric" ]]; then
        log "Using local binaries..."
        cp target/release/aetheric-agent "$AETHERIC_HOME/bin/"
        cp target/release/aetheric "$AETHERIC_HOME/bin/"
    else
        log "Building from source..."
        # Install Rust if not present
        if ! command -v cargo &> /dev/null; then
            log "Installing Rust..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source ~/.cargo/env
        fi
        
        # Build the project
        cargo build --release
        cp target/release/aetheric-agent "$AETHERIC_HOME/bin/"
        cp target/release/aetheric "$AETHERIC_HOME/bin/"
    fi
    
    # Make binaries executable
    chmod +x "$AETHERIC_HOME/bin/aetheric-agent"
    chmod +x "$AETHERIC_HOME/bin/aetheric"
    
    # Set ownership
    chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/aetheric-agent"
    chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/aetheric"
    
    # Create symlinks for global access
    ln -sf "$AETHERIC_HOME/bin/aetheric" /usr/local/bin/aetheric
    ln -sf "$AETHERIC_HOME/bin/aetheric-agent" /usr/local/bin/aetheric-agent
    
    log_success "Aetheric Edge binaries installed"
}

# Configure Mosquitto MQTT broker
configure_mosquitto() {
    log "Configuring Mosquitto MQTT broker..."
    
    # Stop mosquitto if running
    systemctl stop mosquitto 2>/dev/null || true
    
    # Create mosquitto user data directory
    mkdir -p "$MOSQUITTO_DATA_DIR"
    chown mosquitto:mosquitto "$MOSQUITTO_DATA_DIR"
    
    # Create main mosquitto configuration
    cat > "$MOSQUITTO_CONFIG_DIR/mosquitto.conf" << 'EOF'
# Aetheric Edge Mosquitto Configuration
# Local MQTT broker for edge computing

# =============================================================================
# General configuration
# =============================================================================

# Run as mosquitto user
user mosquitto

# Process ID file location
pid_file /var/run/mosquitto/mosquitto.pid

# Data persistence
persistence true
persistence_location /var/lib/mosquitto/

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_dest stdout
log_type error
log_type warning
log_type notice
log_type information
log_timestamp true
connection_messages true

# =============================================================================
# Local MQTT broker settings
# =============================================================================

# Local listener (for edge components)
listener 1883 127.0.0.1
protocol mqtt
allow_anonymous true

# WebSocket listener (for web interfaces)
listener 9001 127.0.0.1
protocol websockets
allow_anonymous true

# =============================================================================
# Message handling
# =============================================================================

# Maximum queued messages per client
max_queued_messages 1000

# Message size limit (1MB)
message_size_limit 1048576

# Keep alive settings
keepalive_interval 60

# =============================================================================
# Bridge configuration (will be configured per cloud)
# =============================================================================

# Bridge configurations will be added dynamically
# by aetheric CLI when connecting to cloud providers
include_dir /etc/mosquitto/conf.d

EOF

    # Create conf.d directory for dynamic bridge configurations
    mkdir -p "$MOSQUITTO_CONFIG_DIR/conf.d"
    
    # Create log directory
    mkdir -p /var/log/mosquitto
    chown mosquitto:mosquitto /var/log/mosquitto
    
    # Set permissions
    chown mosquitto:mosquitto "$MOSQUITTO_CONFIG_DIR/mosquitto.conf"
    chmod 644 "$MOSQUITTO_CONFIG_DIR/mosquitto.conf"
    
    log_success "Mosquitto configured"
}

# Create default Aetheric Edge configuration
create_default_config() {
    log "Creating default Aetheric Edge configuration..."
    
    # Generate a unique gateway ID
    GATEWAY_ID="aetheric-$(hostname)-$(date +%s | tail -c 6)"
    
    cat > "$AETHERIC_CONFIG_DIR/aetheric.toml" << EOF
# Aetheric Edge Configuration
# Generated on $(date)

[gateway]
id = "$GATEWAY_ID"
name = "Aetheric Edge Device"
location = ""
description = "Aetheric Edge IoT Gateway"

[mqtt]
host = "127.0.0.1"
port = 1883
username = ""
password = ""
tls = false
ca_cert_path = "$AETHERIC_CERTS_DIR/ca-cert.pem"
client_cert_path = "$AETHERIC_CERTS_DIR/device-cert.pem"
client_key_path = "$AETHERIC_CERTS_DIR/device-key.pem"

[certificates]
cert_dir = "$AETHERIC_CERTS_DIR"
auto_renew = true
renew_days_threshold = 30

[health]
report_interval_seconds = 30
metrics_enabled = true

[plugins]
install_dir = "$AETHERIC_DATA_DIR/plugins"
temp_dir = "$AETHERIC_DATA_DIR/temp"
docker_enabled = true
max_concurrent_installs = 2

[ssh]
enabled = false
port = 22
max_sessions = 5
session_timeout_minutes = 60

[logging]
level = "info"
file = "$AETHERIC_LOG_DIR/aetheric-agent.log"
max_size_mb = 10
max_files = 5

EOF

    # Set ownership and permissions
    chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_CONFIG_DIR/aetheric.toml"
    chmod 640 "$AETHERIC_CONFIG_DIR/aetheric.toml"
    
    log_success "Default configuration created with Gateway ID: $GATEWAY_ID"
}

# Note: systemd service creation is handled by the gateway install script
# This allows for dynamic user-specific configuration paths

# Create cloud bridge configuration helper
create_bridge_helper() {
    log "Creating cloud bridge configuration helper..."
    
    # Copy the enhanced bridge configuration script
    if [[ -f "scripts/configure-bridge.sh" ]]; then
        cp "scripts/configure-bridge.sh" "$AETHERIC_HOME/bin/"
        chmod +x "$AETHERIC_HOME/bin/configure-bridge.sh"
        chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/configure-bridge.sh"
        
        # Create a symlink for global access
        ln -sf "$AETHERIC_HOME/bin/configure-bridge.sh" /usr/local/bin/aetheric-bridge
        
        log_success "Enhanced bridge configuration helper installed"
    else
        log_warning "Enhanced bridge script not found, creating basic version..."
        
        # Create a basic bridge helper if the enhanced version is not available
        cat > "$AETHERIC_HOME/bin/configure-bridge.sh" << 'EOF'
#!/bin/bash
echo "Basic bridge configuration helper"
echo "For full functionality, please use the enhanced version from the repository"
echo "Usage: aetheric-bridge <provider> <endpoint> [options]"
EOF
        chmod +x "$AETHERIC_HOME/bin/configure-bridge.sh"
        chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/configure-bridge.sh"
        
        log_success "Basic bridge configuration helper created"
    fi
}

# Enable and start services
start_services() {
    log "Enabling and starting services..."
    
    # Enable and start mosquitto
    systemctl enable mosquitto
    systemctl start mosquitto
    
    # Check mosquitto status
    if systemctl is-active --quiet mosquitto; then
        log_success "Mosquitto MQTT broker started"
    else
        log_error "Failed to start Mosquitto"
        exit 1
    fi
    
    # Note: aetheric-agent service will be created by gateway install script
    log_success "Mosquitto service configured and started"
}

# Create CLI wrapper for easy access
create_cli_wrapper() {
    log "Creating CLI wrapper..."
    
    cat > /usr/local/bin/aetheric-cli << 'EOF'
#!/bin/bash

# Aetheric Edge CLI Wrapper
# Provides convenient commands for managing Aetheric Edge

COMMAND="$1"
shift

case "$COMMAND" in
    "status")
        echo "=== Aetheric Edge Status ==="
        echo "Agent Status:"
        systemctl status aetheric-agent --no-pager -l
        echo ""
        echo "MQTT Broker Status:"
        systemctl status mosquitto --no-pager -l
        echo ""
        echo "Active Connections:"
        ss -tulpn | grep :1883
        ;;
    "start")
        echo "Starting Aetheric Edge services..."
        sudo systemctl start mosquitto aetheric-agent
        ;;
    "stop")
        echo "Stopping Aetheric Edge services..."
        sudo systemctl stop aetheric-agent mosquitto
        ;;
    "restart")
        echo "Restarting Aetheric Edge services..."
        sudo systemctl restart mosquitto aetheric-agent
        ;;
    "logs")
        SERVICE="${1:-aetheric-agent}"
        echo "=== $SERVICE Logs ==="
        journalctl -u "$SERVICE" -f
        ;;
    "config")
        aetheric "$@"
        ;;
    "cert")
        aetheric cert "$@"
        ;;
    "connect")
        PROVIDER="$1"
        ENDPOINT="$2"
        shift 2
        echo "Connecting to $PROVIDER at $ENDPOINT..."
        # Use the enhanced bridge configuration script
        if command -v aetheric-bridge &> /dev/null; then
            aetheric-bridge "$PROVIDER" "$ENDPOINT" "$@"
        else
            /opt/aetheric-edge/bin/configure-bridge.sh "$PROVIDER" "$ENDPOINT" "$@"
        fi
        ;;
    *)
        echo "Aetheric Edge CLI"
        echo "Usage: aetheric-cli <command> [options]"
        echo ""
        echo "Commands:"
        echo "  status    - Show service status"
        echo "  start     - Start all services"
        echo "  stop      - Stop all services"
        echo "  restart   - Restart all services"
        echo "  logs      - Show service logs"
        echo "  config    - Manage configuration"
        echo "  cert      - Manage certificates"
        echo "  connect   - Connect to cloud provider"
        echo ""
        echo "Examples:"
        echo "  aetheric-cli status"
        echo "  aetheric-cli logs aetheric-agent"
        echo "  aetheric-cli connect aws your-endpoint.iot.region.amazonaws.com --cert-auth"
        echo "  aetheric-cli connect azure myhub.azure-devices.net --mixed-auth --username 'hub/device' --password 'sas-token'"
        echo "  aetheric-cli connect custom mqtt.example.com --username-auth --username user --password pass"
        ;;
esac

EOF

    chmod +x /usr/local/bin/aetheric-cli
    
    log_success "CLI wrapper created"
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "================================================================"
    echo "             Aetheric Edge Installation Script"
    echo "================================================================"
    echo -e "${NC}"
    echo "This script will install Aetheric Edge with:"
    echo "  • Local MQTT broker (Mosquitto)"
    echo "  • Aetheric Edge agent service"
    echo "  • Cloud bridge configuration"
    echo "  • Management CLI tools"
    echo ""
    
    # Confirm installation
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Run installation steps
    check_root
    detect_os
    create_user
    create_directories
    install_dependencies
    install_binaries
    configure_mosquitto
    create_default_config
    create_bridge_helper
    start_services
    create_cli_wrapper
    
    echo ""
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}             Aetheric Edge Installation Complete!${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo ""
    echo "📋 Installation Summary:"
    echo "  • Aetheric Edge installed in: $AETHERIC_HOME"
    echo "  • Configuration file: $AETHERIC_CONFIG_DIR/aetheric.toml"
    echo "  • Certificates directory: $AETHERIC_CERTS_DIR"
    echo "  • Local MQTT broker: mosquitto://127.0.0.1:1883"
    echo "  • Agent service: Will be created by gateway install script"
    echo ""
    echo "🚀 Next Steps:"
    echo "  1. Configure your gateway settings:"
    echo "     aetheric config set gateway.name 'My Edge Device'"
    echo ""
    echo "  2. Generate device certificates:"
    echo "     aetheric cert create \$(hostname)"
    echo ""
    echo "  3. Use gateway install script to configure and start agent"
    echo ""
    echo "  4. Check status:"
    echo "     aetheric-cli status"
    echo ""
    echo "  5. Connect to cloud (examples):"
    echo "     # AWS with certificates:"
    echo "     aetheric-cli connect aws your-endpoint.iot.region.amazonaws.com --cert-auth"
    echo "     # Azure with mixed auth:"
    echo "     aetheric-cli connect azure myhub.azure-devices.net --mixed-auth --username 'hub/device' --password 'sas-token'"
    echo "     # Custom broker with username/password:"
    echo "     aetheric-cli connect custom mqtt.example.com --username-auth --username user --password pass"
    echo ""
    echo "📖 Documentation:"
    echo "  • Configuration: cat $AETHERIC_CONFIG_DIR/aetheric.toml"
    echo "  • Logs: journalctl -u aetheric-agent -f"
    echo "  • MQTT test: mosquitto_pub -h 127.0.0.1 -t ae/test -m 'Hello Edge'"
    echo ""
    echo -e "${YELLOW}Note: The agent is not started automatically. Configure it first, then start with:${NC}"
    echo -e "${YELLOW}sudo systemctl start aetheric-agent${NC}"
}

# Run main function
main "$@"