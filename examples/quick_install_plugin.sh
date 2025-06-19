#!/bin/bash
# Quick example of installing a plugin via MQTT message to ~/.aetheric/plugins

# First, ensure the directories exist
mkdir -p ~/.aetheric/plugins
mkdir -p ~/.aetheric/tmp
mkdir -p ~/.aetheric/logs

echo "🚀 Demonstrating plugin installation to ~/.aetheric/plugins"
echo ""

# Create a simple plugin script
cat > /tmp/hello-plugin.sh << 'EOF'
#!/bin/bash
# Hello World Plugin for Aetheric Edge
echo "Hello from Aetheric Edge Plugin!"
echo "Plugin location: $(pwd)"
echo "Time: $(date)"
echo "User: $(whoami)"
echo "No sudo required! 🎉"

# Simulate some work
for i in {1..5}; do
    echo "Working... $i/5"
    sleep 1
done

echo "Plugin execution complete!"
EOF

# Base64 encode the plugin
PLUGIN_B64=$(base64 < /tmp/hello-plugin.sh)

# Create the MQTT command message JSON
cat > /tmp/install-command.json << EOF
{
  "id": "$(uuidgen)",
  "command": {
    "type": "install",
    "plugin_name": "hello-world",
    "source": {
      "type": "base64",
      "data": "$PLUGIN_B64"
    },
    "config": {
      "name": "hello-world",
      "version": "1.0.0",
      "description": "Simple hello world plugin",
      "plugin_type": "binary",
      "auto_start": false,
      "environment": {},
      "dependencies": [],
      "ports": [],
      "volumes": [],
      "command_args": []
    }
  },
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "parameters": {}
}
EOF

echo "📄 Created plugin installation command:"
echo "   Plugin will be installed to: ~/.aetheric/plugins/hello-world/"
echo ""
echo "To install this plugin via MQTT, publish the message to:"
echo "   Topic: aetheric/gateway/{gateway-id}/command"
echo "   Payload: $(cat /tmp/install-command.json)"
echo ""
echo "Or use the aetheric CLI:"
echo "   aetheric mqtt pub aetheric/gateway/test-device/command -f /tmp/install-command.json"
echo ""

# Show what the installed structure would look like
echo "📁 After installation, you'll have:"
echo "   ~/.aetheric/plugins/"
echo "   └── hello-world/"
echo "       ├── plugin.sh       (the executable)"
echo "       └── plugin.toml     (configuration)"
echo ""
echo "No sudo required! You own everything in ~/.aetheric/"

# Cleanup
rm -f /tmp/hello-plugin.sh