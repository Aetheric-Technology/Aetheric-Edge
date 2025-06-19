#!/bin/bash
# Demo: Install a plugin to ~/.aetheric/plugins (no sudo required)

echo "🏠 Demo: Installing plugin to ~/.aetheric/plugins"
echo "   No sudo required!"
echo ""

# Ensure directories exist
mkdir -p ~/.aetheric/plugins/demo-plugin

# Create a sample monitoring plugin
cat > ~/.aetheric/plugins/demo-plugin/plugin.sh << 'EOF'
#!/bin/bash
# Demo Monitoring Plugin for Aetheric Edge
echo "🔍 Demo Plugin v1.0 - Monitoring User Home"
echo "📍 Installed in: $(dirname $0)"
echo "👤 Running as: $(whoami)"
echo "🏠 Home directory: $HOME"
echo "✅ No sudo required!"
echo ""

# Check disk usage
echo "💾 Home directory usage:"
du -sh ~ 2>/dev/null | awk '{print "   " $1}'

# Check available space
echo "💽 Available disk space:"
df -h ~ | tail -1 | awk '{print "   " $4 " available"}'

# List plugin directory contents
echo "📁 Plugin directory contents:"
ls -la "$(dirname $0)" | while read line; do
    echo "   $line"
done

echo ""
echo "🎉 Plugin execution complete!"
EOF

# Make it executable
chmod +x ~/.aetheric/plugins/demo-plugin/plugin.sh

# Create a configuration file
cat > ~/.aetheric/plugins/demo-plugin/plugin.toml << EOF
name = "demo-plugin"
version = "1.0.0"
description = "Demo monitoring plugin for user home directory"
plugin_type = "script"
auto_start = false
dependencies = []
ports = []
volumes = []
command_args = []

[environment]
LOG_LEVEL = "info"
PLUGIN_HOME = "~/.aetheric/plugins/demo-plugin"
EOF

# Create a simple metadata file
cat > ~/.aetheric/plugins/demo-plugin/README.md << EOF
# Demo Plugin

This is a demonstration plugin installed in the user's home directory.

## Features
- No sudo required
- Monitors home directory usage
- Shows plugin directory contents
- Safe and isolated

## Installation Location
\`~/.aetheric/plugins/demo-plugin/\`

## Files
- \`plugin.sh\` - Main executable
- \`plugin.toml\` - Configuration
- \`README.md\` - This file

## Usage
\`\`\`bash
~/.aetheric/plugins/demo-plugin/plugin.sh
\`\`\`
EOF

echo "✅ Demo plugin installed successfully!"
echo ""
echo "📍 Location: ~/.aetheric/plugins/demo-plugin/"
echo ""
echo "📋 Files created:"
ls -la ~/.aetheric/plugins/demo-plugin/ | while read line; do
    echo "   $line"
done

echo ""
echo "🚀 Run the plugin:"
echo "   ~/.aetheric/plugins/demo-plugin/plugin.sh"
echo ""
echo "📁 Plugin directory ownership:"
ls -ld ~/.aetheric/plugins/demo-plugin/ | awk '{print "   Owner: " $3 ":" $4 "  Permissions: " $1}'

echo ""
echo "🎯 This demonstrates how Aetheric Edge can install plugins"
echo "   in user-owned directories without requiring sudo!"