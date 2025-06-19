# Plugin Directory Configuration

This document explains the plugin directory configuration for Aetheric Edge and why `~/.aetheric/plugins` is the preferred default.

## 🏠 Default: `~/.aetheric/plugins` (Recommended)

**All plugin installations use `~/.aetheric/plugins` by default - no sudo required!**

### ✅ Why This is Perfect:

1. **No sudo required** - User owns the directory
2. **Standard Unix convention** - Follows patterns like `~/.docker`, `~/.kube`, `~/.ssh`
3. **Easy management** - Users can backup, inspect, modify their plugins
4. **Security** - Each user has isolated plugins
5. **Development friendly** - Perfect for testing and development

### 📁 Directory Structure:
```
~/.aetheric/
├── config/         # Configuration files
├── plugins/        # Plugin installations (PRIMARY LOCATION)
├── certs/          # SSL certificates
├── logs/           # Application logs
└── tmp/            # Temporary files
```

## 🔧 Code Implementation

### Default Configuration:
```rust
impl Default for AethericConfig {
    fn default() -> Self {
        // Default to user home directory - no sudo required!
        let plugins_dir = home.join(".aetheric").join("plugins");
        // ...
    }
}
```

### Automatic Directory Creation:
```rust
impl PluginManager {
    pub fn new(config: Arc<AethericConfig>) -> Self {
        // Ensures ~/.aetheric/plugins exists on startup
        self.ensure_directories();
    }
}
```

### Path Expansion Support:
```rust
// Supports both absolute and tilde paths
install_dir = "~/.aetheric/plugins"  # Expands to /Users/username/.aetheric/plugins
install_dir = "/absolute/path"       # Uses as-is
```

## 🎯 Usage Examples

### 1. MQTT Plugin Installation:
```json
{
  "command": {
    "type": "install",
    "plugin_name": "my-monitor",
    "source": {
      "type": "base64",
      "data": "base64-encoded-plugin"
    }
  }
}
```
→ Installs to: `~/.aetheric/plugins/my-monitor/`

### 2. Configuration:
```toml
[plugins]
install_dir = "~/.aetheric/plugins"  # Default - no sudo required
temp_dir = "~/.aetheric/tmp"
docker_enabled = true
```

### 3. Manual Installation:
```bash
mkdir -p ~/.aetheric/plugins/my-plugin
cp my-script.sh ~/.aetheric/plugins/my-plugin/plugin.sh
chmod +x ~/.aetheric/plugins/my-plugin/plugin.sh
```

## 🚨 Special Cases Only

### System-wide Deployment (Requires Sudo):
Only use system directories when:
- Running as a system service without user home
- Enterprise deployment requiring shared plugins
- Docker container without persistent home

```toml
# Special case configuration (aetheric-production.toml)
[plugins]
install_dir = "/opt/aetheric-edge/plugins"  # Requires sudo
temp_dir = "/tmp/aetheric-edge"
```

### Fallback Behavior:
```rust
// Code automatically falls back to system directories
// only when home directory is not available
if let Some(home) = dirs::home_dir() {
    plugins_dir = home.join(".aetheric").join("plugins");  // Preferred
} else {
    warn!("Home directory not available, falling back to system directories");
    plugins_dir = PathBuf::from("/opt/aetheric-edge/plugins");  // Fallback
}
```

## 📋 Configuration Files

### Primary: `~/.aetheric/config/aetheric.toml`
```toml
[plugins]
install_dir = "~/.aetheric/plugins"    # Default - no sudo!
temp_dir = "~/.aetheric/tmp"
```

### Production: `aetheric-production.toml`
```toml
[plugins]
install_dir = "/opt/aetheric-edge/plugins"  # Special case - requires sudo
temp_dir = "/tmp/aetheric-edge"
```

## 🧪 Testing

All tests verify the default behavior:
```bash
cargo test test_default_paths
```

Tests confirm:
- ✅ Default config uses `~/.aetheric/plugins`
- ✅ No sudo required for default directories
- ✅ Path expansion works (`~` → `/Users/username`)
- ✅ Directory consistency under `~/.aetheric/`
- ✅ PluginManager creates directories automatically

## 🎉 Summary

**`~/.aetheric/plugins` is the primary plugin directory for all normal usage.**

- **Default behavior**: Uses `~/.aetheric/plugins` (no sudo required)
- **Special cases**: Falls back to system directories only when necessary
- **Configuration**: Can be overridden if needed, but default is perfect
- **User experience**: Simple, secure, and doesn't require elevated permissions

This approach makes Aetheric Edge developer-friendly while still supporting production deployments when needed.