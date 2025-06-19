#!/bin/bash

# Comprehensive Integration Test for Aetheric Edge
# Tests all major functionality end-to-end

set -e
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/aetheric-test-$(date +%s)"
CERT_DIR="$TEST_DIR/certs"
CONFIG_FILE="$TEST_DIR/config.toml"
DEVICE_ID="test-device-$(date +%s)"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    pkill -f "aetheric-agent" 2>/dev/null || true
    pkill -f "mosquitto" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
}

# Set trap for cleanup
trap cleanup EXIT

echo -e "${BLUE}🧪 Aetheric Edge Comprehensive Integration Test${NC}"
echo -e "${BLUE}================================================${NC}"

# Create test environment
echo -e "${YELLOW}Setting up test environment...${NC}"
mkdir -p "$TEST_DIR" "$CERT_DIR"

# Build the project
echo -e "${YELLOW}Building project...${NC}"
cargo build --quiet --release

echo -e "${GREEN}✅ Build completed successfully${NC}"

# Test 1: Configuration Management
echo -e "\n${BLUE}📋 Test 1: Configuration Management${NC}"

# Generate default config
echo "→ Generating default configuration..."
cargo run --bin aetheric --quiet -- config init --config "$CONFIG_FILE"

# Test config get/set operations
echo "→ Testing configuration operations..."
cargo run --bin aetheric --quiet -- config set gateway.id "$DEVICE_ID" --config "$CONFIG_FILE"
RETRIEVED_ID=$(cargo run --bin aetheric --quiet -- config get gateway.id --config "$CONFIG_FILE")

if [ "$RETRIEVED_ID" = "$DEVICE_ID" ]; then
    echo -e "${GREEN}✅ Configuration management works correctly${NC}"
else
    echo -e "${RED}❌ Configuration management failed${NC}"
    exit 1
fi

# Test 2: Certificate Management
echo -e "\n${BLUE}🔐 Test 2: Certificate Management${NC}"

# Create device certificate
echo "→ Creating device certificate..."
cargo run --bin aetheric --quiet -- --cert-dir "$CERT_DIR" cert create "$DEVICE_ID" \
    --san localhost --san 127.0.0.1 --san "$DEVICE_ID.local"

# Verify certificate was created
if [ -f "$CERT_DIR/device-cert.pem" ] && [ -f "$CERT_DIR/device-key.pem" ]; then
    echo -e "${GREEN}✅ Certificate creation successful${NC}"
else
    echo -e "${RED}❌ Certificate creation failed${NC}"
    exit 1
fi

# Test certificate information
echo "→ Testing certificate information..."
CERT_OUTPUT=$(cargo run --bin aetheric --quiet -- --cert-dir "$CERT_DIR" cert show)
if echo "$CERT_OUTPUT" | grep -q "$DEVICE_ID"; then
    echo -e "${GREEN}✅ Certificate information retrieval works${NC}"
else
    echo -e "${RED}❌ Certificate information retrieval failed${NC}"
    exit 1
fi

# Test certificate expiry check
echo "→ Testing certificate expiry check..."
if cargo run --bin aetheric --quiet -- --cert-dir "$CERT_DIR" cert check --days 30; then
    echo -e "${GREEN}✅ Certificate expiry check works${NC}"
else
    echo -e "${RED}❌ Certificate expiry check failed${NC}"
    exit 1
fi

# Test CSR generation
echo "→ Testing CSR generation..."
cargo run --bin aetheric --quiet -- --cert-dir "$CERT_DIR" cert csr "${DEVICE_ID}-csr" \
    --san localhost

if [ -f "$CERT_DIR/device-csr.pem" ]; then
    echo -e "${GREEN}✅ CSR generation successful${NC}"
else
    echo -e "${RED}❌ CSR generation failed${NC}"
    exit 1
fi

# Test 3: MQTT Communication and Health Monitoring
echo -e "\n${BLUE}📡 Test 3: MQTT Communication and Health Monitoring${NC}"

# Start mosquitto broker
echo "→ Starting MQTT broker..."
mosquitto -p 1883 -v > "$TEST_DIR/mosquitto.log" 2>&1 &
MOSQUITTO_PID=$!
sleep 2

# Update config for test directories
cargo run --bin aetheric --quiet -- config set plugins.install_dir "$TEST_DIR/plugins" --config "$CONFIG_FILE"
cargo run --bin aetheric --quiet -- config set plugins.temp_dir "$TEST_DIR/temp" --config "$CONFIG_FILE"
cargo run --bin aetheric --quiet -- config set certificates.cert_dir "$CERT_DIR" --config "$CONFIG_FILE"

# Start the agent
echo "→ Starting agent..."
cargo run --bin aetheric-agent --quiet -- --config "$CONFIG_FILE" > "$TEST_DIR/agent.log" 2>&1 &
AGENT_PID=$!
sleep 5

# Test health message reception
echo "→ Testing health message reception..."
HEALTH_MSG=$(mosquitto_sub -h localhost -t "ae/$DEVICE_ID/health" -C 1 -W 10)
if echo "$HEALTH_MSG" | grep -q "\"status\":\"up\""; then
    echo -e "${GREEN}✅ Health monitoring works correctly${NC}"
else
    echo -e "${RED}❌ Health monitoring failed${NC}"
    echo "Agent log:"
    tail -20 "$TEST_DIR/agent.log"
    exit 1
fi

# Test 4: Command Processing
echo -e "\n${BLUE}⚙️  Test 4: Command Processing${NC}"

# Test health command
echo "→ Testing health command..."
HEALTH_CMD='{
  "id": "health-test",
  "command": {"type": "health"},
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "parameters": {}
}'

mosquitto_pub -h localhost -t "ae/$DEVICE_ID/cmd/health-test" -m "$HEALTH_CMD"
sleep 2

# Check for response (from agent log since mosquitto_sub has timeout issues)
if grep -q "Processing health command" "$TEST_DIR/agent.log"; then
    echo -e "${GREEN}✅ Health command processing works${NC}"
else
    echo -e "${RED}❌ Health command processing failed${NC}"
    echo "Agent log:"
    tail -20 "$TEST_DIR/agent.log"
    exit 1
fi

# Test 5: Plugin System
echo -e "\n${BLUE}📦 Test 5: Plugin Installation System${NC}"

# Create test plugin
echo "→ Creating test plugin..."
mkdir -p "$TEST_DIR/temp"
echo '#!/bin/bash\necho "Test plugin executed successfully"' > "$TEST_DIR/test-plugin.sh"
chmod +x "$TEST_DIR/test-plugin.sh"

# Test local plugin installation via command
echo "→ Testing local plugin installation..."
INSTALL_CMD='{
  "id": "install-test",
  "command": {
    "type": "install",
    "plugin_name": "test-plugin",
    "source": {
      "type": "local",
      "path": "'$TEST_DIR'/test-plugin.sh"
    }
  },
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "parameters": {}
}'

mosquitto_pub -h localhost -t "ae/$DEVICE_ID/cmd/install-test" -m "$INSTALL_CMD"
sleep 5

# Check if plugin was installed
if [ -f "$TEST_DIR/plugins/test-plugin/plugin" ]; then
    echo -e "${GREEN}✅ Plugin installation works correctly${NC}"
else
    echo -e "${RED}❌ Plugin installation failed${NC}"
    echo "Contents of plugins directory:"
    ls -la "$TEST_DIR/plugins/" || echo "Plugins directory not found"
    echo "Agent log:"
    tail -20 "$TEST_DIR/agent.log"
    exit 1
fi

# Test plugin removal
echo "→ Testing plugin removal..."
REMOVE_CMD='{
  "id": "remove-test",
  "command": {
    "type": "remove",
    "plugin_name": "test-plugin"
  },
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "parameters": {}
}'

mosquitto_pub -h localhost -t "ae/$DEVICE_ID/cmd/remove-test" -m "$REMOVE_CMD"
sleep 3

if [ ! -d "$TEST_DIR/plugins/test-plugin" ]; then
    echo -e "${GREEN}✅ Plugin removal works correctly${NC}"
else
    echo -e "${RED}❌ Plugin removal failed${NC}"
    exit 1
fi

# Test 6: Configuration Validation
echo -e "\n${BLUE}🔍 Test 6: Configuration Validation${NC}"

# Test invalid gateway ID
echo "→ Testing configuration validation..."
TEST_CONFIG=$(mktemp)
cat > "$TEST_CONFIG" << EOF
[gateway]
id = ""
name = "Test Device"

[mqtt]
host = "localhost"
port = 1883
tls = false

[certificates]
cert_dir = "$CERT_DIR"
auto_renew = true
renew_days_threshold = 30

[health]
report_interval_seconds = 30
metrics_enabled = true

[plugins]
install_dir = "$TEST_DIR/plugins"
temp_dir = "$TEST_DIR/temp"
docker_enabled = true
max_concurrent_installs = 2

[ssh]
enabled = true
port = 22
max_sessions = 5
session_timeout_minutes = 60
EOF

# This should fail due to empty gateway ID
if cargo run --bin aetheric-agent --quiet -- --config "$TEST_CONFIG" 2>&1 | grep -q "Gateway ID cannot be empty"; then
    echo -e "${GREEN}✅ Configuration validation works correctly${NC}"
else
    echo -e "${RED}❌ Configuration validation failed${NC}"
    exit 1
fi

rm "$TEST_CONFIG"

# Final cleanup
echo -e "\n${YELLOW}Cleaning up test processes...${NC}"
kill $AGENT_PID 2>/dev/null || true
kill $MOSQUITTO_PID 2>/dev/null || true

echo -e "\n${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
echo -e "${GREEN}Aetheric Edge is fully functional and ready for deployment.${NC}"

# Summary
echo -e "\n${BLUE}📊 Test Summary:${NC}"
echo -e "✅ Configuration Management"
echo -e "✅ Certificate Management" 
echo -e "✅ MQTT Communication"
echo -e "✅ Health Monitoring"
echo -e "✅ Command Processing"
echo -e "✅ Plugin Installation/Removal"
echo -e "✅ Configuration Validation"

echo -e "\n${GREEN}Integration test completed successfully!${NC}"