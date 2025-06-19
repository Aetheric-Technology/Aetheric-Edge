#!/bin/bash

# Aetheric Edge Demo Script
# This script demonstrates the basic setup and usage of both CLI and agent

set -e

echo "🚀 Aetheric Edge Demo"
echo "===================="

# Build the project
echo "📦 Building Aetheric Edge..."
cargo build --quiet

echo ""
echo "🔧 Setting up configuration..."

# Initialize configuration
echo "  → Initializing default configuration"
cargo run --bin aetheric --quiet -- config init

# Show the configuration
echo "  → Current configuration:"
cargo run --bin aetheric --quiet -- config show

echo ""
echo "🔐 Setting up certificates..."

# Create a device certificate
echo "  → Creating device certificate for 'demo-device'"
cargo run --bin aetheric --quiet -- cert create demo-device --san localhost --san 127.0.0.1 --san demo-device.local

# Show certificate information
echo "  → Certificate information:"
cargo run --bin aetheric --quiet -- cert show

# Check certificate validity
echo "  → Checking certificate validity:"
if cargo run --bin aetheric --quiet -- cert check --days 30; then
    echo "    ✅ Certificate is valid"
else
    echo "    ❌ Certificate is invalid or expiring soon"
fi

echo ""
echo "⚙️  Configuration management..."

# Update some configuration values
echo "  → Setting gateway ID to demo-device"
cargo run --bin aetheric --quiet -- config set gateway.id demo-device

echo "  → Setting MQTT host to localhost"
cargo run --bin aetheric --quiet -- config set mqtt.host localhost

echo "  → Getting gateway ID:"
GATEWAY_ID=$(cargo run --bin aetheric --quiet -- config get gateway.id)
echo "    Gateway ID: $GATEWAY_ID"

echo ""
echo "🎯 Ready to run the agent!"
echo ""
echo "To start the agent, run:"
echo "  cargo run --bin aetheric-agent --quiet"
echo ""
echo "The agent will:"
echo "  • Connect to MQTT broker at localhost:1883"
echo "  • Use device certificate for authentication (if TLS enabled)"
echo "  • Report health status every 30 seconds"
echo "  • Listen for commands on topic: ae/demo-device/cmd/+"
echo "  • Respond to commands on topic: ae/demo-device/cmd/[id]/response"
echo ""
echo "Demo completed! 🎉"