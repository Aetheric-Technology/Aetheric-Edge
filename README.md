# Aetheric Edge

A simplified edge computing agent inspired by thin-edge.io, built in Rust for high performance and reliability.

Aetheric Edge consists of two main components:
- **aetheric-agent**: The main edge agent that handles MQTT communication and device management
- **aetheric**: A CLI tool for certificate management, configuration, and device setup

## Features

- **MQTT-based Communication**: Reliable messaging using MQTT protocol
- **Certificate Management**: X.509 certificate generation, renewal, and validation
- **Health Monitoring**: Automatic health status reporting with system metrics
- **Plugin Management**: Install and manage software plugins (binaries and Docker containers)
- **OTA Updates**: Over-the-air update capabilities
- **Command Processing**: Remote command execution via MQTT
- **Configuration Management**: TOML-based configuration with CLI tools
- **SSH over MQTT**: Secure remote access through MQTT tunnels (planned)
- **Lightweight**: Minimal resource footprint optimized for edge devices

## Architecture

Aetheric Edge follows a modular architecture with these core components:

- **MQTT Client**: Handles all MQTT communication with auto-reconnection
- **Agent**: Core orchestration and command processing
- **Health Monitor**: System health tracking and reporting
- **Command Handler**: Processes incoming commands and manages responses
- **Configuration Manager**: TOML-based configuration with validation

## Quick Start

### Installation

```bash
# Clone and build
git clone <repository-url>
cd aetheric-edge
cargo build --release

# Install both binaries
cargo install --path . --bins
```

This will install:
- `aetheric-agent`: The main edge agent
- `aetheric`: The management CLI tool

### Setup and Configuration

1. **Initialize Configuration**:
```bash
aetheric config init
```

2. **Create Device Certificate**:
```bash
aetheric cert create my-device-001 --san localhost --san 192.168.1.100
```

3. **Configure Device Settings**:
```bash
aetheric config set gateway.id my-device-001
aetheric config set mqtt.host mqtt.example.com
```

4. **View Configuration**:
```bash
aetheric config show
```

### Running the Agent

```bash
# Run with default configuration
aetheric-agent

# Run with custom config file
aetheric-agent --config /path/to/aetheric.toml

# Generate default config file
aetheric-agent --generate-config

# Enable verbose logging
aetheric-agent --verbose
```

### Certificate Management

```bash
# Create device certificate
aetheric cert create device-001 --san localhost --san 192.168.1.100

# Create certificate signing request
aetheric cert csr device-001 --san localhost

# Show certificate information
aetheric cert show

# Check certificate expiry
aetheric cert check --days 30

# Renew certificate
aetheric cert renew device-001 --san localhost

# Remove certificates
aetheric cert remove
```

## MQTT Topics

Aetheric Edge uses the following MQTT topic structure:

```
ae/{gateway_id}/health          - Health status reports
ae/{gateway_id}/cmd/{cmd_id}    - Incoming commands
ae/{gateway_id}/cmd/{cmd_id}/response - Command responses
ae/{gateway_id}/telemetry       - System telemetry data
ae/{gateway_id}/events          - System events
ae/{gateway_id}/ota/status      - OTA update status
ae/{gateway_id}/ssh/{session_id} - SSH tunnel data
```

## Commands

### Health Check
```json
{
  "id": "health-001",
  "command": {"type": "health"},
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

### Install Plugin from URL
```json
{
  "id": "install-001",
  "command": {
    "type": "install",
    "plugin_name": "sensor-monitor",
    "source": {
      "type": "url",
      "url": "https://example.com/plugin.bin",
      "checksum": "md5-hash-here"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

### Install Docker Container
```json
{
  "id": "install-002",
  "command": {
    "type": "install",
    "plugin_name": "data-processor",
    "source": {
      "type": "docker",
      "image": "myregistry/data-processor",
      "tag": "v1.2.3"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

### OTA Update
```json
{
  "id": "ota-001",
  "command": {
    "type": "ota_update",
    "version": "1.2.0",
    "url": "https://example.com/aetheric-edge-v1.2.0.bin",
    "checksum": "sha256-hash-here"
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

### Remove Plugin
```json
{
  "id": "remove-001",
  "command": {
    "type": "remove",
    "plugin_name": "old-plugin"
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

### System Restart
```json
{
  "id": "restart-001",
  "command": {"type": "restart"},
  "timestamp": "2024-01-01T12:00:00Z",
  "parameters": {}
}
```

## Health Monitoring

The agent automatically reports system health every 30 seconds (configurable) including:

- Gateway ID and status (up/down/degraded)
- System uptime
- Memory usage
- CPU usage percentage
- Timestamp

## Plugin System

Aetheric Edge supports multiple plugin installation methods:

1. **Binary Plugins**: Download and install executable binaries
2. **Docker Containers**: Pull and manage Docker containers
3. **Local Files**: Install from local file system

Plugins are installed to `/opt/aetheric-edge/plugins/` by default and can be managed remotely via MQTT commands.

## Configuration

Key configuration sections:

- **Gateway**: Device identification and metadata
- **MQTT**: Broker connection settings and authentication
- **Health**: Monitoring intervals and feature flags
- **Plugins**: Installation directories and Docker settings
- **SSH**: Remote access configuration

## Development

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Running with Debug Logging

```bash
RUST_LOG=debug cargo run -- --verbose
```

## Roadmap

- [ ] SSH over MQTT implementation
- [ ] TLS/SSL support for MQTT
- [ ] Plugin sandboxing and security
- [ ] Web UI for management
- [ ] Cloud provider integrations
- [ ] Advanced monitoring and alerting

## CLI Tools

### aetheric (Management CLI)

The `aetheric` CLI tool provides device management capabilities similar to thin-edge.io's `tedge` command:

```bash
# Certificate operations
aetheric cert create <device-id> [--san <hostname>]
aetheric cert show
aetheric cert check [--days <threshold>]
aetheric cert renew <device-id>

# Configuration management  
aetheric config init
aetheric config show
aetheric config get <key>
aetheric config set <key> <value>
```

### aetheric-agent (Edge Agent)

The `aetheric-agent` is the main daemon process similar to `tedge-agent`:

```bash
# Basic usage
aetheric-agent                    # Run with default config
aetheric-agent --verbose          # Enable debug logging
aetheric-agent --config <path>    # Use custom config file
aetheric-agent --generate-config  # Create default config
```

## Comparison with thin-edge.io

Aetheric Edge is inspired by thin-edge.io but focuses on simplicity and core functionality:

| Feature | thin-edge.io | Aetheric Edge |
|---------|--------------|---------------|
| MQTT Communication | ✅ | ✅ |
| Health Monitoring | ✅ | ✅ |
| Software Management | ✅ | ✅ (Binary + Docker) |
| Certificate Management | ✅ (tedge cert) | ✅ (aetheric cert) |
| Configuration CLI | ✅ (tedge config) | ✅ (aetheric config) |
| Cloud Integrations | ✅ (C8y, AWS, Azure) | ❌ (Generic MQTT) |
| SSH over MQTT | ✅ | 🚧 (Planned) |
| Plugin Architecture | ✅ (Complex) | ✅ (Simplified) |
| Multi-tenancy | ✅ | ❌ |
| Service Management | ✅ (systemd) | ❌ (Manual) |

## License

MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.