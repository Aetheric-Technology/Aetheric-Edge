# Aetheric Edge Plugin Management System

The Aetheric Edge plugin management system provides comprehensive remote plugin installation, management, and lifecycle control via MQTT commands. This document provides examples and usage instructions for all supported plugin operations.

## Overview

The plugin management system supports:
- **Binary Plugins**: Executable files managed as systemd services
- **Docker Plugins**: Container-based plugins
- **APT Packages**: System packages via apt package manager
- **Script Plugins**: Shell scripts managed as systemd services

## Plugin Installation Methods

### 1. Binary Plugin from URL

Install a binary plugin by downloading from a URL:

```json
{
  "id": "install-001",
  "command": {
    "type": "install",
    "plugin_name": "my-sensor-reader",
    "source": {
      "type": "url",
      "url": "https://releases.example.com/sensor-reader/v1.2.3/sensor-reader-linux-amd64",
      "checksum": "d85b1213473c2fd7c2045020a6b9c62b",
      "checksum_type": "md5"
    },
    "config": {
      "name": "my-sensor-reader",
      "version": "1.2.3",
      "description": "Temperature and humidity sensor reader",
      "plugin_type": "binary",
      "auto_start": true,
      "environment": {
        "SENSOR_PORT": "/dev/ttyUSB0",
        "UPDATE_INTERVAL": "30"
      },
      "command_args": ["--config", "/etc/sensor-reader.conf"],
      "dependencies": [],
      "ports": [8080],
      "volumes": []
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### 2. Base64 Encoded Binary

Upload a small binary directly encoded in base64:

```json
{
  "id": "install-002",
  "command": {
    "type": "install",
    "plugin_name": "logger-plugin",
    "source": {
      "type": "base64",
      "data": "IyEvYmluL2Jhc2gKZWNobyAiSGVsbG8gZnJvbSBsb2dnZXIgcGx1Z2luISIKd2hpbGUgdHJ1ZTsgZG8KICBkYXRlID4+IC90bXAvbG9nZ2VyLmxvZwogIHNsZWVwIDEwCmRvbmU=",
      "checksum": "a1b2c3d4e5f6789",
      "checksum_type": "md5"
    },
    "config": {
      "name": "logger-plugin",
      "version": "1.0.0",
      "description": "Simple logging plugin",
      "plugin_type": "script",
      "auto_start": true,
      "environment": {},
      "command_args": [],
      "dependencies": [],
      "ports": [],
      "volumes": []
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### 3. Docker Plugin

Install a Docker container as a plugin:

```json
{
  "id": "install-003",
  "command": {
    "type": "install",
    "plugin_name": "mqtt-bridge",
    "source": {
      "type": "docker",
      "image": "eclipse-mosquitto",
      "tag": "2.0.15",
      "registry": "docker.io"
    },
    "config": {
      "name": "mqtt-bridge",
      "version": "2.0.15",
      "description": "MQTT broker bridge",
      "plugin_type": "docker",
      "auto_start": true,
      "environment": {
        "MOSQUITTO_USERNAME": "admin",
        "MOSQUITTO_PASSWORD": "secret"
      },
      "command_args": ["/mosquitto/config/mosquitto.conf"],
      "dependencies": [],
      "ports": [1883, 9001],
      "volumes": ["/opt/mosquitto/config:/mosquitto/config", "/opt/mosquitto/data:/mosquitto/data"]
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### 4. APT Package

Install a system package via APT:

```json
{
  "id": "install-004",
  "command": {
    "type": "install",
    "plugin_name": "nginx-proxy",
    "source": {
      "type": "apt_package",
      "package": "nginx",
      "version": "1.18.0-6ubuntu14.4",
      "repository": "ppa:nginx/stable"
    },
    "config": {
      "name": "nginx-proxy",
      "version": "1.18.0",
      "description": "Nginx reverse proxy",
      "plugin_type": "apt_package",
      "auto_start": true,
      "environment": {},
      "command_args": [],
      "dependencies": [],
      "ports": [80, 443],
      "volumes": []
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### 5. Chunked Transfer (Large Files)

For large binaries that exceed MQTT message size limits:

**Chunk 1:**
```json
{
  "id": "install-005-chunk-1",
  "command": {
    "type": "install",
    "plugin_name": "large-binary",
    "source": {
      "type": "chunked",
      "chunk_id": "large-binary-upload-001",
      "total_chunks": 3,
      "chunk_index": 0,
      "data": "H4sIAAAAAAAAA+y9...", 
      "checksum": "final_file_checksum_here"
    },
    "config": {
      "name": "large-binary",
      "version": "2.1.0",
      "description": "Large binary plugin",
      "plugin_type": "binary",
      "auto_start": false,
      "environment": {},
      "command_args": [],
      "dependencies": [],
      "ports": [],
      "volumes": []
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

**Chunks 2 and 3 follow similar pattern with chunk_index 1 and 2**

## Plugin Management Commands

### Start Plugin

```json
{
  "id": "start-001",
  "command": {
    "type": "start",
    "plugin_name": "my-sensor-reader"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### Stop Plugin

```json
{
  "id": "stop-001",
  "command": {
    "type": "stop",
    "plugin_name": "my-sensor-reader"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### Restart Plugin

```json
{
  "id": "restart-001",
  "command": {
    "type": "restart",
    "plugin_name": "my-sensor-reader"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### Update Plugin

```json
{
  "id": "update-001",
  "command": {
    "type": "update",
    "plugin_name": "my-sensor-reader",
    "source": {
      "type": "url",
      "url": "https://releases.example.com/sensor-reader/v1.2.4/sensor-reader-linux-amd64",
      "checksum": "f96c2213473c2fd7c2045020a6b9c62b",
      "checksum_type": "md5"
    },
    "config": {
      "name": "my-sensor-reader",
      "version": "1.2.4",
      "description": "Temperature and humidity sensor reader (updated)",
      "plugin_type": "binary",
      "auto_start": true,
      "environment": {
        "SENSOR_PORT": "/dev/ttyUSB0",
        "UPDATE_INTERVAL": "30"
      },
      "command_args": ["--config", "/etc/sensor-reader.conf"],
      "dependencies": [],
      "ports": [8080],
      "volumes": []
    }
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### Remove Plugin

```json
{
  "id": "remove-001",
  "command": {
    "type": "remove",
    "plugin_name": "my-sensor-reader"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### Get Plugin Status

**Single Plugin:**
```json
{
  "id": "status-001",
  "command": {
    "type": "status",
    "plugin_name": "my-sensor-reader"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

**All Plugins:**
```json
{
  "id": "status-002",
  "command": {
    "type": "status"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

### List All Plugins

```json
{
  "id": "list-001",
  "command": {
    "type": "list"
  },
  "timestamp": "2025-06-18T15:30:00Z",
  "parameters": {}
}
```

## Response Examples

### Successful Installation Response

```json
{
  "command_id": "install-001",
  "status": "success",
  "message": "Command executed successfully",
  "timestamp": "2025-06-18T15:31:00Z",
  "result": {
    "plugin_name": "my-sensor-reader",
    "status": "installed",
    "path": "/home/user/.aetheric/data/plugins/my-sensor-reader",
    "binary": "/home/user/.aetheric/data/plugins/my-sensor-reader/plugin",
    "service_name": "aetheric-plugin-my-sensor-reader"
  }
}
```

### Plugin Status Response

```json
{
  "command_id": "status-001",
  "status": "success",
  "message": "Command executed successfully",
  "timestamp": "2025-06-18T15:31:00Z",
  "result": {
    "plugin_name": "my-sensor-reader",
    "version": "1.2.3",
    "status": "running",
    "plugin_type": "binary",
    "pid": null,
    "install_time": "2025-06-18T15:30:15Z",
    "last_started": "2025-06-18T15:30:30Z"
  }
}
```

### Plugin List Response

```json
{
  "command_id": "list-001",
  "status": "success",
  "message": "Command executed successfully",
  "timestamp": "2025-06-18T15:31:00Z",
  "result": {
    "plugins": [
      {
        "plugin_name": "my-sensor-reader",
        "version": "1.2.3",
        "status": "running",
        "plugin_type": "binary"
      },
      {
        "plugin_name": "mqtt-bridge",
        "version": "2.0.15",
        "status": "running", 
        "plugin_type": "docker"
      }
    ],
    "total_count": 2
  }
}
```

## MQTT Topics

### Command Topic Structure
```
ae/{gateway_id}/cmd/{command_id}
```

**Example:**
```
ae/aetheric-device-001/cmd/install-001
```

### Response Topic Structure  
```
ae/{gateway_id}/cmd/{command_id}/response
```

**Example:**
```
ae/aetheric-device-001/cmd/install-001/response
```

## Plugin File Structure

Each installed plugin creates the following directory structure:

```
~/.aetheric/data/plugins/{plugin_name}/
├── plugin                 # Main executable (for binary/script plugins)
├── plugin.sh             # Script file (for script plugins)
├── plugin.toml           # Plugin configuration
└── logs/                 # Plugin-specific logs (optional)
```

## Systemd Service Management

Binary and script plugins are automatically managed as systemd services:

- **Service Name:** `aetheric-plugin-{plugin_name}`
- **Service File:** `/etc/systemd/system/aetheric-plugin-{plugin_name}.service`
- **User:** `aetheric`
- **Auto-restart:** Yes (if configured)
- **Logging:** systemd journal

### Manual Service Management

You can also manage plugins using standard systemd commands:

```bash
# Check plugin status
sudo systemctl status aetheric-plugin-my-sensor-reader

# View plugin logs
journalctl -u aetheric-plugin-my-sensor-reader -f

# Manually start/stop (not recommended - use MQTT commands instead)
sudo systemctl start aetheric-plugin-my-sensor-reader
sudo systemctl stop aetheric-plugin-my-sensor-reader
```

## Security Considerations

1. **Checksum Verification:** Always provide checksums for downloaded binaries
2. **Plugin Isolation:** Plugins run under the `aetheric` user with limited privileges
3. **Network Security:** Use TLS for MQTT communication in production
4. **Code Signing:** Consider implementing code signing verification for production use

## Troubleshooting

### Common Issues

1. **Plugin Installation Fails**
   - Check network connectivity for URL downloads
   - Verify checksums match
   - Ensure sufficient disk space

2. **Plugin Won't Start**
   - Check plugin logs: `journalctl -u aetheric-plugin-{name} -f`
   - Verify binary permissions and dependencies
   - Check environment variables and configuration

3. **Docker Plugin Issues**
   - Ensure Docker daemon is running
   - Check if image exists and can be pulled
   - Verify port mappings don't conflict

4. **APT Package Problems**
   - Check if package exists in repository
   - Verify APT sources are configured correctly
   - Ensure sufficient privileges for installation

### Log Locations

- **Agent Logs:** `journalctl -u aetheric-agent -f`
- **Plugin Logs:** `journalctl -u aetheric-plugin-{name} -f`
- **MQTT Logs:** `journalctl -u mosquitto -f`

## Example: Complete Plugin Installation Workflow

Here's a complete example of installing, monitoring, and managing a plugin:

1. **Install Plugin:**
   ```bash
   mosquitto_pub -h localhost -t "ae/my-device/cmd/install-001" -m '{
     "id": "install-001",
     "command": {
       "type": "install",
       "plugin_name": "temperature-sensor",
       "source": {
         "type": "url",
         "url": "https://releases.example.com/temp-sensor/v1.0.0/temp-sensor-linux-amd64",
         "checksum": "d85b1213473c2fd7c2045020a6b9c62b"
       },
       "config": {
         "name": "temperature-sensor",
         "version": "1.0.0",
         "plugin_type": "binary",
         "auto_start": true,
         "environment": {"SENSOR_ID": "temp-001"},
         "ports": [8081]
       }
     },
     "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
     "parameters": {}
   }'
   ```

2. **Check Installation Status:**
   ```bash
   mosquitto_pub -h localhost -t "ae/my-device/cmd/status-001" -m '{
     "id": "status-001",
     "command": {"type": "status", "plugin_name": "temperature-sensor"},
     "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
     "parameters": {}
   }'
   ```

3. **Monitor Responses:**
   ```bash
   mosquitto_sub -h localhost -t "ae/my-device/cmd/+/response"
   ```

This plugin management system provides complete remote control over edge device plugins via MQTT, making it easy to deploy, update, and manage distributed IoT applications.