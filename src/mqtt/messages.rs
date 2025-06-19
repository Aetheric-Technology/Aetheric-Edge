use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMessage {
    pub status: HealthStatus,
    pub timestamp: String,
    pub gateway_id: String,
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Up,
    Down,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandMessage {
    pub id: String,
    pub command: CommandType,
    pub timestamp: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommandType {
    Install {
        plugin_name: String,
        source: PluginSource,
        config: Option<PluginConfig>,
    },
    Update {
        plugin_name: String,
        source: PluginSource,
        config: Option<PluginConfig>,
    },
    Remove {
        plugin_name: String,
    },
    Start {
        plugin_name: String,
    },
    Stop {
        plugin_name: String,
    },
    Restart {
        plugin_name: String,
    },
    Status {
        plugin_name: Option<String>, // None for all plugins
    },
    List,
    OtaUpdate {
        version: String,
        url: String,
        checksum: Option<String>,
    },
    SshConnect {
        session_id: String,
        target_host: Option<String>,
        target_port: Option<u16>,
        duration_minutes: Option<u32>,
    },
    SshDisconnect {
        session_id: String,
    },
    SshData {
        session_id: String,
        data: String, // base64 encoded data
        direction: SshDataDirection,
    },
    SshHeartbeat {
        session_id: String,
    },
    Health,
    SystemRestart,
    EnablePlugin {
        plugin_name: String,
    },
    DisablePlugin {
        plugin_name: String,
    },
    SetPluginMaintenance {
        plugin_name: String,
        maintenance_mode: bool,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PluginSource {
    Url {
        url: String,
        checksum: Option<String>,
        checksum_type: Option<String>, // md5, sha256, etc.
    },
    Base64 {
        data: String,
        checksum: Option<String>,
        checksum_type: Option<String>,
    },
    AptPackage {
        package: String,
        version: Option<String>,
        repository: Option<String>,
    },
    Docker {
        image: String,
        tag: Option<String>,
        registry: Option<String>,
    },
    Chunked {
        chunk_id: String,
        total_chunks: u32,
        chunk_index: u32,
        data: String,             // base64 encoded chunk
        checksum: Option<String>, // final file checksum
    },
    Local {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub plugin_type: PluginType,
    pub auto_start: bool,
    pub environment: HashMap<String, String>,
    pub dependencies: Vec<String>,
    pub ports: Vec<u16>,
    pub volumes: Vec<String>, // For Docker plugins
    pub command_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    Binary,
    Docker,
    AptPackage,
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshDataDirection {
    Up,   // Client to server (upstream)
    Down, // Server to client (downstream)
}

// Legacy support - keep old InstallSource for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InstallSource {
    Url {
        url: String,
        checksum: Option<String>,
    },
    Docker {
        image: String,
        tag: Option<String>,
    },
    Local {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub command_id: String,
    pub status: CommandStatus,
    pub message: String,
    pub timestamp: String,
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CommandStatus {
    Received,
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryMessage {
    pub timestamp: String,
    pub metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMessage {
    pub id: String,
    pub event_type: String,
    pub message: String,
    pub timestamp: String,
    pub severity: EventSeverity,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaStatus {
    pub current_version: String,
    pub target_version: Option<String>,
    pub status: OtaUpdateStatus,
    pub progress_percent: Option<u8>,
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtaUpdateStatus {
    Idle,
    Downloading,
    Installing,
    Success,
    Failed,
}

impl CommandMessage {
    pub fn new(command: CommandType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            command,
            timestamp: chrono::Utc::now().to_rfc3339(),
            parameters: HashMap::new(),
        }
    }
}

impl CommandResponse {
    pub fn new(command_id: String, status: CommandStatus, message: String) -> Self {
        Self {
            command_id,
            status,
            message,
            timestamp: chrono::Utc::now().to_rfc3339(),
            result: None,
        }
    }

    pub fn with_result(mut self, result: serde_json::Value) -> Self {
        self.result = Some(result);
        self
    }
}

impl EventMessage {
    pub fn new(event_type: String, message: String, severity: EventSeverity) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            message,
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}
