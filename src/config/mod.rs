use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AethericConfig {
    pub gateway: GatewayConfig,
    pub mqtt: MqttConfig,
    pub certificates: CertificateConfig,
    pub health: HealthConfig,
    pub plugins: PluginsConfig,
    pub ssh: SshConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub id: String,
    pub name: Option<String>,
    pub location: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub ca_cert_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub cert_dir: PathBuf,
    pub auto_renew: bool,
    pub renew_days_threshold: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub report_interval_seconds: u64,
    pub metrics_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    pub install_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub docker_enabled: bool,
    pub max_concurrent_installs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub enabled: bool,
    pub port: u16,
    pub max_sessions: usize,
    pub session_timeout_minutes: u32,
}

impl Default for AethericConfig {
    fn default() -> Self {
        // Default to user home directory - no sudo required!
        let (_aetheric_dir, cert_dir, plugins_dir, temp_dir) = if let Some(home) = dirs::home_dir()
        {
            let aetheric_home = home.join(".aetheric");
            (
                aetheric_home.clone(),
                aetheric_home.join("certs"),
                aetheric_home.join("plugins"),
                aetheric_home.join("tmp"),
            )
        } else {
            // Fallback to system directories only if home directory is not available
            // This is a special case (e.g., running as system service without home)
            tracing::warn!("Home directory not available, falling back to system directories");

            #[cfg(windows)]
            let (config_dir, cert_dir, plugin_dir, temp_dir) = {
                let program_data =
                    std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
                let base = PathBuf::from(program_data).join("AethericEdge");
                (
                    base.clone(),
                    base.join("certs"),
                    base.join("plugins"),
                    std::env::temp_dir().join("aetheric-edge"),
                )
            };

            #[cfg(target_os = "macos")]
            let (config_dir, cert_dir, plugin_dir, temp_dir) = (
                PathBuf::from("/Library/Application Support/AethericEdge"),
                PathBuf::from("/Library/Application Support/AethericEdge/certs"),
                PathBuf::from("/usr/local/lib/aetheric-edge/plugins"),
                PathBuf::from("/tmp/aetheric-edge"),
            );

            #[cfg(target_os = "linux")]
            let (config_dir, cert_dir, plugin_dir, temp_dir) = (
                PathBuf::from("/etc/aetheric-edge"),
                PathBuf::from("/etc/aetheric-edge/certs"),
                PathBuf::from("/opt/aetheric-edge/plugins"),
                PathBuf::from("/tmp/aetheric-edge"),
            );

            (config_dir, cert_dir, plugin_dir, temp_dir)
        };

        Self {
            gateway: GatewayConfig {
                id: "aetheric-edge-001".to_string(),
                name: Some("Aetheric Edge Device".to_string()),
                location: None,
                description: None,
            },
            mqtt: MqttConfig {
                host: "localhost".to_string(),
                port: 1883,
                username: None,
                password: None,
                tls: false,
                ca_cert_path: Some(cert_dir.join("ca-cert.pem")),
                client_cert_path: Some(cert_dir.join("device-cert.pem")),
                client_key_path: Some(cert_dir.join("device-key.pem")),
            },
            certificates: CertificateConfig {
                cert_dir,
                auto_renew: true,
                renew_days_threshold: 30,
            },
            health: HealthConfig {
                report_interval_seconds: 30,
                metrics_enabled: true,
            },
            plugins: PluginsConfig {
                install_dir: plugins_dir,
                temp_dir,
                docker_enabled: true,
                max_concurrent_installs: 2,
            },
            ssh: SshConfig {
                enabled: true,
                port: 22,
                max_sessions: 5,
                session_timeout_minutes: 60,
            },
        }
    }
}

impl AethericConfig {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            tracing::info!(
                "Config file not found at {:?}, creating default config",
                path
            );
            let default_config = Self::default();
            default_config.save_to_file(path)?;
            return Ok(default_config);
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: AethericConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;

        config.validate()?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config to TOML")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {:?}", path))?;

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.gateway.id.is_empty() {
            anyhow::bail!("Gateway ID cannot be empty");
        }

        if self.gateway.id.len() > 64 {
            anyhow::bail!("Gateway ID cannot be longer than 64 characters");
        }

        if !self
            .gateway
            .id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!(
                "Gateway ID can only contain alphanumeric characters, hyphens, and underscores"
            );
        }

        if self.mqtt.host.is_empty() {
            anyhow::bail!("MQTT host cannot be empty");
        }

        if self.mqtt.port == 0 {
            anyhow::bail!("MQTT port cannot be zero");
        }

        if self.health.report_interval_seconds == 0 {
            anyhow::bail!("Health report interval must be greater than zero");
        }

        Ok(())
    }

    pub fn get_config_path() -> PathBuf {
        if let Ok(config_dir) = std::env::var("AETHERIC_CONFIG_DIR") {
            PathBuf::from(config_dir).join("aetheric.toml")
        } else if let Some(home) = dirs::home_dir() {
            // Primary: ~/.aetheric/config/aetheric.toml (consistent with plugin directory)
            let primary_config = home.join(".aetheric").join("config").join("aetheric.toml");
            if primary_config.exists() {
                return primary_config;
            }

            // Secondary: ~/.config/aetheric-edge/aetheric.toml (XDG standard)
            let xdg_config = home
                .join(".config")
                .join("aetheric-edge")
                .join("aetheric.toml");
            if xdg_config.exists() {
                return xdg_config;
            }

            // Default to primary location for new installations
            primary_config
        } else {
            // Fallback for special cases (system service without home directory)
            PathBuf::from("/etc/aetheric-edge/aetheric.toml")
        }
    }

    /// Expands a path that may contain ~ to the user's home directory
    pub fn expand_path(path: &Path) -> PathBuf {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(&path_str[2..]);
                }
            }
        }
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config_validation() {
        let config = AethericConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = AethericConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed_config: AethericConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.gateway.id, parsed_config.gateway.id);
    }

    #[test]
    fn test_config_file_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_path_buf();

        let original_config = AethericConfig::default();
        original_config.save_to_file(&config_path).unwrap();

        let loaded_config = AethericConfig::load_from_file(&config_path).unwrap();
        assert_eq!(original_config.gateway.id, loaded_config.gateway.id);
    }
}
