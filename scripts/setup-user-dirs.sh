#!/bin/bash
# Setup user-accessible directories for Aetheric Edge (no sudo required)

# Define the base directory in user's home
AETHERIC_HOME="$HOME/.aetheric"

echo "Setting up Aetheric Edge user directories..."

# Create directory structure
mkdir -p "$AETHERIC_HOME/plugins"
mkdir -p "$AETHERIC_HOME/tmp"
mkdir -p "$AETHERIC_HOME/certs"
mkdir -p "$AETHERIC_HOME/logs"
mkdir -p "$AETHERIC_HOME/config"

# Set proper permissions (user-only access for security)
chmod 700 "$AETHERIC_HOME"
chmod 700 "$AETHERIC_HOME/certs"
chmod 755 "$AETHERIC_HOME/plugins"
chmod 755 "$AETHERIC_HOME/tmp"
chmod 755 "$AETHERIC_HOME/logs"
chmod 755 "$AETHERIC_HOME/config"

# Copy example config if it doesn't exist
if [ ! -f "$AETHERIC_HOME/config/aetheric.toml" ]; then
    echo "Creating default configuration..."
    cat > "$AETHERIC_HOME/config/aetheric.toml" << EOF
[gateway]
id = "aetheric-edge-001"
name = "Aetheric Edge Device"
location = "Home"
description = "Personal edge device"

[mqtt]
host = "localhost"
port = 1883
username = ""
password = ""
tls = false

[certificates]
cert_dir = "$AETHERIC_HOME/certs"
auto_renew = true
renew_days_threshold = 30

[health]
report_interval_seconds = 30
metrics_enabled = true

[plugins]
install_dir = "$AETHERIC_HOME/plugins"
temp_dir = "$AETHERIC_HOME/tmp"
docker_enabled = true
max_concurrent_installs = 2

[ssh]
enabled = true
port = 22
max_sessions = 5
session_timeout_minutes = 60
EOF
fi

echo "✅ Aetheric Edge user directories created successfully!"
echo ""
echo "Directory structure:"
echo "  $AETHERIC_HOME/"
echo "  ├── config/     - Configuration files"
echo "  ├── plugins/    - Installed plugins (no sudo required)"
echo "  ├── certs/      - SSL certificates"
echo "  ├── logs/       - Application logs"
echo "  └── tmp/        - Temporary files"
echo ""
echo "To use this configuration, set the environment variable:"
echo "  export AETHERIC_CONFIG_DIR=$AETHERIC_HOME/config"
echo ""
echo "Or run the agent with:"
echo "  aetheric-agent --config $AETHERIC_HOME/config/aetheric.toml"