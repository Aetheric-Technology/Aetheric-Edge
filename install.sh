#!/bin/bash

# Aetheric Edge Installation Script
# Installs Aetheric Edge with local MQTT broker (Mosquitto)
# Enterprise IoT edge computing platform

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
    
    # Always stop services before replacing binaries
    log "Stopping any running services..."
    systemctl stop aetheric-agent 2>/dev/null || true
    
    # Remove old binaries and symlinks
    log "Removing old binaries..."
    rm -f "$AETHERIC_HOME/bin/aetheric-agent" "$AETHERIC_HOME/bin/aetheric"
    rm -f /usr/local/bin/aetheric /usr/local/bin/aetheric-agent
    
    # For now, we'll build from source since we don't have GitHub releases yet
    # In production, this would download pre-built binaries from GitHub releases
    
    if [[ -f "target/release/aetheric-agent" ]] && [[ -f "target/release/aetheric" ]]; then
        log "Using local binaries..."
        cp -f target/release/aetheric-agent "$AETHERIC_HOME/bin/"
        cp -f target/release/aetheric "$AETHERIC_HOME/bin/"
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
        cp -f target/release/aetheric-agent "$AETHERIC_HOME/bin/"
        cp -f target/release/aetheric "$AETHERIC_HOME/bin/"
    fi
    
    # Make binaries executable
    chmod +x "$AETHERIC_HOME/bin/aetheric-agent"
    chmod +x "$AETHERIC_HOME/bin/aetheric"
    
    # Set ownership
    chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/aetheric-agent"
    chown "$AETHERIC_USER:$AETHERIC_USER" "$AETHERIC_HOME/bin/aetheric"
    
    # Create fresh symlinks for global access
    ln -sf "$AETHERIC_HOME/bin/aetheric" /usr/local/bin/aetheric
    ln -sf "$AETHERIC_HOME/bin/aetheric-agent" /usr/local/bin/aetheric-agent
    
    log_success "Aetheric Edge binaries installed (replaced existing)"
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
persistence_file mosquitto.db

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

# Message handling and retention for 7-day offline support
max_queued_messages 0
max_queued_bytes 0
queue_qos0_messages true
retain_available true
persistent_client_expiration 7d

# Message size limit (1MB)
max_packet_size 1048576

# =============================================================================
# Bridge configuration directory
# =============================================================================

# Bridge configurations can be added here if needed
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
    
    # Always backup existing config if present
    if [[ -f "$AETHERIC_CONFIG_DIR/aetheric.toml" ]]; then
        log "Backing up existing configuration..."
        cp "$AETHERIC_CONFIG_DIR/aetheric.toml" "$AETHERIC_CONFIG_DIR/aetheric.toml.backup.$(date +%s)"
    fi
    
    # Generate a unique gateway ID
    GATEWAY_ID="aetheric-$(hostname)-$(date +%s | tail -c 6)"
    
    # Always create fresh config
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

    # Set ownership and permissions (config should be owned by the actual user, not aetheric system user)
    chown "$ACTUAL_USER:$ACTUAL_USER" "$AETHERIC_CONFIG_DIR/aetheric.toml"
    chmod 640 "$AETHERIC_CONFIG_DIR/aetheric.toml"
    
    log_success "Default configuration created with Gateway ID: $GATEWAY_ID"
}

# Create systemd service for aetheric-agent
create_systemd_service() {
    log "Creating systemd service for aetheric-agent..."
    
    # Get the actual user who invoked sudo
    ACTUAL_USER="${SUDO_USER:-$USER}"
    ACTUAL_HOME=$(eval echo "~$ACTUAL_USER")
    
    # Always stop and disable existing service first
    log "Stopping any existing aetheric-agent service..."
    systemctl stop aetheric-agent.service 2>/dev/null || true
    systemctl disable aetheric-agent.service 2>/dev/null || true
    
    # Always create fresh service file (overwrites existing)
    log "Creating fresh systemd service file..."
    cat > "$SYSTEMD_DIR/aetheric-agent.service" << EOF
[Unit]
Description=Aetheric Edge Agent - MQTT-based edge computing agent
Documentation=https://github.com/Aetheric-Technology/Aetheric-Edge
After=network.target mosquitto.service
Wants=network.target
Requires=mosquitto.service

[Service]
Type=simple
User=$ACTUAL_USER
Group=$ACTUAL_USER
WorkingDirectory=$ACTUAL_HOME
RuntimeDirectory=aetheric-agent
ExecStartPre=+-/usr/local/bin/aetheric init
ExecStart=/usr/local/bin/aetheric-agent --config $ACTUAL_HOME/.aetheric/aetheric.toml
Restart=always
RestartSec=10
StartLimitBurst=5
Environment="HOME=$ACTUAL_HOME"
Environment="USER=$ACTUAL_USER"

[Install]
WantedBy=multi-user.target
EOF

    # Set permissions
    chmod 644 "$SYSTEMD_DIR/aetheric-agent.service"
    
    # Reload systemd to pick up changes
    systemctl daemon-reload
    
    log_success "Systemd service created for user: $ACTUAL_USER"
    log "Service will run as: $ACTUAL_USER with config: $ACTUAL_HOME/.aetheric/config/aetheric.toml"
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
    
    # Enable and attempt to start aetheric-agent service
    systemctl enable aetheric-agent
    
    # Try to start aetheric-agent (will auto-restart if it fails due to dependencies)
    log "Starting Aetheric Agent..."
    if systemctl start aetheric-agent; then
        log_success "Aetheric Agent started successfully"
    else
        log_warning "Aetheric Agent failed to start initially - it will auto-restart when dependencies are ready"
    fi
    
    log_success "Services configured - Mosquitto started, Aetheric Agent enabled with auto-restart"
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
    
    # Check for -y flag to skip confirmation
    SKIP_CONFIRM=false
    for arg in "$@"; do
        if [[ "$arg" == "-y" || "$arg" == "--yes" ]]; then
            SKIP_CONFIRM=true
            break
        fi
    done
    
    # Confirm installation (unless -y flag is used)
    if [[ "$SKIP_CONFIRM" == "false" ]]; then
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Installation cancelled."
            exit 0
        fi
    else
        echo "Auto-confirmed with -y flag"
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
    create_systemd_service
    start_services
    
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
    echo "  • Agent service: aetheric-agent.service (created, not started)"
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
    echo "     systemctl status aetheric-agent mosquitto"
    echo ""
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