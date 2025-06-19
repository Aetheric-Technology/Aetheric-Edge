#!/bin/bash

# Test script for aetheric-edge command functionality

set -e

echo "🧪 Testing Aetheric Edge Commands"
echo "=================================="

# Start the agent in background
echo "Starting agent..."
cargo run --bin aetheric-agent --quiet -- --verbose > /tmp/agent.log 2>&1 &
AGENT_PID=$!

# Wait for agent to start
sleep 3

echo "Agent started (PID: $AGENT_PID)"

# Test health command
echo ""
echo "📊 Testing health command..."
HEALTH_CMD='{
  "id": "health-test-001",
  "command": {"type": "health"},
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "parameters": {}
}'

mosquitto_pub -h localhost -t "ae/test-device-001/cmd/health-test-001" -m "$HEALTH_CMD"

# Wait for response
echo "Waiting for health response..."
HEALTH_RESPONSE=$(mosquitto_sub -h localhost -t "ae/test-device-001/cmd/health-test-001/response" -C 1 -W 5)
echo "Health response: $HEALTH_RESPONSE"

# Test install command
echo ""
echo "📦 Testing plugin install command..."
INSTALL_CMD='{
  "id": "install-test-001",
  "command": {
    "type": "install",
    "plugin_name": "test-plugin",
    "source": {
      "type": "local",
      "path": "/bin/echo"
    }
  },
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "parameters": {}
}'

mosquitto_pub -h localhost -t "ae/test-device-001/cmd/install-test-001" -m "$INSTALL_CMD"

# Wait for response
echo "Waiting for install response..."
INSTALL_RESPONSE=$(mosquitto_sub -h localhost -t "ae/test-device-001/cmd/install-test-001/response" -C 1 -W 10)
echo "Install response: $INSTALL_RESPONSE"

# Clean up
echo ""
echo "Cleaning up..."
kill $AGENT_PID 2>/dev/null || true
pkill mosquitto || true

echo "✅ Command testing completed!"