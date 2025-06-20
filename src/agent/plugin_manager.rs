use crate::config::AethericConfig;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    Binary,
    Docker,
    AptPackage,
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub status: PluginStatus,
    pub path: PathBuf,
    pub pid: Option<u32>,
    pub config: PluginConfig,
    pub install_time: String,
    pub last_started: Option<String>,
    pub restart_count: u32,
    pub last_health_check: Option<String>,
    pub health_check_failures: u32,
    pub enabled: bool,
    pub maintenance_mode: bool,
    pub maintenance_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealthStatus {
    pub plugin_name: String,
    pub status: PluginStatus,
    pub uptime_seconds: u64,
    pub restart_count: u32,
    pub health_check_failures: u32,
    pub last_health_check: String,
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub enabled: bool,
    pub maintenance_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginStatus {
    Installing,
    Installed,
    Running,
    Stopped,
    Failed,
    Updating,
    Uninstalling,
    Disabled,
    Maintenance,
    Unhealthy,
    Restarting,
}

#[derive(Clone)]
pub struct PluginManager {
    config: Arc<AethericConfig>,
    chunked_transfers: Arc<tokio::sync::Mutex<HashMap<String, ChunkedTransfer>>>,
}

struct ChunkedTransfer {
    #[allow(dead_code)]
    total_chunks: u32,
    received_chunks: HashMap<u32, Vec<u8>>,
    checksum: Option<String>,
    #[allow(dead_code)]
    plugin_name: String,
    plugin_config: PluginConfig,
}

impl PluginManager {
    pub fn new(config: Arc<AethericConfig>) -> Self {
        let plugin_manager = Self {
            config,
            chunked_transfers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };

        // Ensure plugin directories exist on startup
        if let Err(e) = plugin_manager.ensure_directories() {
            warn!("Failed to create plugin directories: {}", e);
        }

        plugin_manager
    }

    /// Ensure all necessary plugin directories exist
    fn ensure_directories(&self) -> Result<()> {
        use crate::config::AethericConfig;

        // Expand paths that might contain ~
        let install_dir = AethericConfig::expand_path(&self.config.plugins.install_dir);
        let temp_dir = AethericConfig::expand_path(&self.config.plugins.temp_dir);

        info!("Ensuring plugin directories exist:");
        info!("  Install directory: {}", install_dir.display());
        info!("  Temp directory: {}", temp_dir.display());

        std::fs::create_dir_all(&install_dir).with_context(|| {
            format!(
                "Failed to create plugin install directory: {}",
                install_dir.display()
            )
        })?;

        std::fs::create_dir_all(&temp_dir).with_context(|| {
            format!(
                "Failed to create plugin temp directory: {}",
                temp_dir.display()
            )
        })?;

        info!("✅ Plugin directories created successfully (no sudo required!)");
        Ok(())
    }

    pub async fn install_plugin(
        &self,
        plugin_name: &str,
        source: &PluginSource,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin: {} from {:?}", plugin_name, source);

        // Validate plugin name
        if plugin_name.trim().is_empty() {
            return Err(anyhow!("Plugin name cannot be empty"));
        }

        // Set plugin status to installing
        self.set_plugin_status(plugin_name, PluginStatus::Installing)
            .await?;

        match source {
            PluginSource::Url {
                url,
                checksum,
                checksum_type,
            } => {
                self.install_from_url(
                    plugin_name,
                    url,
                    checksum.as_deref(),
                    checksum_type.as_deref(),
                    config,
                )
                .await
            }
            PluginSource::Base64 {
                data,
                checksum,
                checksum_type,
            } => {
                self.install_from_base64(
                    plugin_name,
                    data,
                    checksum.as_deref(),
                    checksum_type.as_deref(),
                    config,
                )
                .await
            }
            PluginSource::AptPackage {
                package,
                version,
                repository,
            } => {
                self.install_apt_package(
                    plugin_name,
                    package,
                    version.as_deref(),
                    repository.as_deref(),
                    config,
                )
                .await
            }
            PluginSource::Docker {
                image,
                tag,
                registry,
            } => {
                self.install_docker_plugin(
                    plugin_name,
                    image,
                    tag.as_deref(),
                    registry.as_deref(),
                    config,
                )
                .await
            }
            PluginSource::Chunked {
                chunk_id,
                total_chunks,
                chunk_index,
                data,
                checksum,
            } => {
                self.handle_chunked_transfer(
                    plugin_name,
                    chunk_id,
                    *total_chunks,
                    *chunk_index,
                    data,
                    checksum.as_deref(),
                    config,
                )
                .await
            }
            PluginSource::Local { path } => {
                self.install_from_local_path(plugin_name, path, config)
                    .await
            }
        }
    }

    pub async fn update_plugin(
        &self,
        plugin_name: &str,
        source: &PluginSource,
        config: Option<PluginConfig>,
    ) -> Result<serde_json::Value> {
        info!("Updating plugin: {}", plugin_name);

        // Stop the plugin if running
        if self.stop_plugin(plugin_name).await.is_ok() {
            info!("Stopped plugin {} for update", plugin_name);
        }

        // Set status to updating
        self.set_plugin_status(plugin_name, PluginStatus::Updating)
            .await?;

        // Get existing config if not provided
        let plugin_config = match config {
            Some(cfg) => cfg,
            None => self.get_plugin_config(plugin_name).await?,
        };

        // Backup current plugin
        self.backup_plugin(plugin_name).await?;

        // Install new version
        match self
            .install_plugin(plugin_name, source, plugin_config)
            .await
        {
            Ok(result) => {
                // Auto-start if configured
                if let Ok(info) = self.get_plugin_info(plugin_name).await {
                    if info.config.auto_start {
                        let _ = self.start_plugin(plugin_name).await;
                    }
                }
                Ok(result)
            }
            Err(e) => {
                warn!("Plugin update failed, restoring backup: {}", e);
                self.restore_plugin_backup(plugin_name).await?;
                Err(e)
            }
        }
    }

    pub async fn remove_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Removing plugin: {}", plugin_name);

        // Set status to uninstalling
        self.set_plugin_status(plugin_name, PluginStatus::Uninstalling)
            .await?;

        // Stop the plugin if running
        if self.stop_plugin(plugin_name).await.is_ok() {
            info!("Stopped plugin {} for removal", plugin_name);
        }

        let plugin_path = self.config.plugins.install_dir.join(plugin_name);

        if plugin_path.exists() {
            // Handle different plugin types
            if let Ok(info) = self.get_plugin_info(plugin_name).await {
                match info.plugin_type {
                    PluginType::Docker => {
                        self.remove_docker_plugin(plugin_name).await?;
                    }
                    PluginType::AptPackage => {
                        self.remove_apt_package(plugin_name).await?;
                    }
                    PluginType::Binary | PluginType::Script => {
                        // Remove systemd service
                        self.remove_systemd_service_for_plugin(plugin_name).await?;
                        // Remove file-based plugins
                        fs::remove_dir_all(&plugin_path).await?;
                    }
                }
            } else {
                // Fallback: remove directory and try to clean up systemd service
                let _ = self.remove_systemd_service_for_plugin(plugin_name).await;
                fs::remove_dir_all(&plugin_path).await?;
            }

            info!("Plugin {} removed successfully", plugin_name);
        } else {
            warn!("Plugin {} not found", plugin_name);
        }

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "removed"
        }))
    }

    pub async fn start_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Starting plugin: {}", plugin_name);

        let info = self.get_plugin_info(plugin_name).await?;

        match info.plugin_type {
            PluginType::Binary | PluginType::Script => {
                self.start_binary_plugin(plugin_name, &info).await
            }
            PluginType::Docker => self.start_docker_plugin(plugin_name, &info).await,
            PluginType::AptPackage => self.start_service_plugin(plugin_name, &info).await,
        }
    }

    pub async fn stop_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Stopping plugin: {}", plugin_name);

        let info = self.get_plugin_info(plugin_name).await?;

        match info.plugin_type {
            PluginType::Binary | PluginType::Script => {
                self.stop_binary_plugin(plugin_name, &info).await
            }
            PluginType::Docker => self.stop_docker_plugin(plugin_name).await,
            PluginType::AptPackage => self.stop_service_plugin(plugin_name).await,
        }
    }

    pub async fn restart_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Restarting plugin: {}", plugin_name);

        let _ = self.stop_plugin(plugin_name).await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        self.start_plugin(plugin_name).await
    }

    pub async fn get_plugin_status(&self, plugin_name: &str) -> Result<serde_json::Value> {
        let info = self.get_plugin_info(plugin_name).await?;

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "version": info.version,
            "status": info.status,
            "plugin_type": info.plugin_type,
            "pid": info.pid,
            "install_time": info.install_time,
            "last_started": info.last_started,
        }))
    }

    pub async fn list_plugins(&self) -> Result<serde_json::Value> {
        let mut plugins = Vec::new();

        let install_dir = &self.config.plugins.install_dir;
        if install_dir.exists() {
            let mut entries = fs::read_dir(install_dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                if entry.file_type().await?.is_dir() {
                    let plugin_name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(status) = self.get_plugin_status(&plugin_name).await {
                        plugins.push(status);
                    }
                }
            }
        }

        Ok(serde_json::json!({
            "plugins": plugins,
            "total_count": plugins.len()
        }))
    }

    // Private helper methods

    async fn install_from_url(
        &self,
        plugin_name: &str,
        url: &str,
        checksum: Option<&str>,
        checksum_type: Option<&str>,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        info!("Downloading plugin from URL: {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout
            .build()?;

        let response = client.get(url).send().await?;
        let content = response.bytes().await?;

        // Verify checksum if provided
        if let Some(expected_checksum) = checksum {
            self.verify_checksum(&content, expected_checksum, checksum_type.unwrap_or("md5"))?;
        }

        self.install_binary_content(plugin_name, &content, config)
            .await
    }

    async fn install_from_base64(
        &self,
        plugin_name: &str,
        data: &str,
        checksum: Option<&str>,
        checksum_type: Option<&str>,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin from base64 data");

        // Validate that base64 data is not empty
        if data.trim().is_empty() {
            return Err(anyhow!("Base64 data cannot be empty"));
        }

        let content = general_purpose::STANDARD
            .decode(data)
            .context("Failed to decode base64 data")?;

        // Validate that decoded content is not empty
        if content.is_empty() {
            return Err(anyhow!("Decoded content cannot be empty"));
        }

        // Verify checksum if provided
        if let Some(expected_checksum) = checksum {
            self.verify_checksum(&content, expected_checksum, checksum_type.unwrap_or("md5"))?;
        }

        self.install_binary_content(plugin_name, &content, config)
            .await
    }

    async fn install_from_local_path(
        &self,
        plugin_name: &str,
        path: &str,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin from local path: {}", path);

        let content = fs::read(path)
            .await
            .with_context(|| format!("Failed to read local file: {}", path))?;

        self.install_binary_content(plugin_name, &content, config)
            .await
    }

    async fn install_apt_package(
        &self,
        plugin_name: &str,
        package: &str,
        version: Option<&str>,
        repository: Option<&str>,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        info!("Installing APT package: {}", package);

        // Add repository if provided
        if let Some(repo) = repository {
            let output = Command::new("sudo")
                .args(["add-apt-repository", "-y", repo])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("Failed to add repository: {}", stderr));
            }

            // Update package list
            let output = Command::new("sudo").args(["apt", "update"]).output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("APT update failed: {}", stderr);
            }
        }

        // Install package
        let package_spec = match version {
            Some(v) => format!("{}={}", package, v),
            None => package.to_string(),
        };

        let output = Command::new("sudo")
            .args(["apt", "install", "-y", &package_spec])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to install APT package: {}", stderr));
        }

        // Save plugin configuration
        self.save_plugin_config(plugin_name, config).await?;

        info!("APT package {} installed successfully", package);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "package": package,
            "version": version,
            "status": "installed"
        }))
    }

    async fn install_docker_plugin(
        &self,
        plugin_name: &str,
        image: &str,
        tag: Option<&str>,
        registry: Option<&str>,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        if !self.config.plugins.docker_enabled {
            return Err(anyhow!("Docker functionality is disabled"));
        }

        let full_image = match (registry, tag) {
            (Some(reg), Some(t)) => format!("{}/{}:{}", reg, image, t),
            (Some(reg), None) => format!("{}/{}:latest", reg, image),
            (None, Some(t)) => format!("{}:{}", image, t),
            (None, None) => format!("{}:latest", image),
        };

        info!("Installing Docker plugin: {}", full_image);

        // Pull the Docker image
        let output = Command::new("docker")
            .args(["pull", &full_image])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to pull Docker image: {}", stderr));
        }

        // Save plugin configuration
        self.save_plugin_config(plugin_name, config).await?;

        info!("Docker plugin {} installed successfully", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "image": full_image,
            "status": "installed"
        }))
    }

    async fn handle_chunked_transfer(
        &self,
        plugin_name: &str,
        chunk_id: &str,
        total_chunks: u32,
        chunk_index: u32,
        data: &str,
        checksum: Option<&str>,
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        // Validate chunk data is not empty
        if data.trim().is_empty() {
            return Err(anyhow!("Chunk data cannot be empty"));
        }

        // Chunks are raw base64 text pieces, not base64-encoded data
        let chunk_data = data.as_bytes().to_vec();

        let mut transfers = self.chunked_transfers.lock().await;

        let transfer = transfers
            .entry(chunk_id.to_string())
            .or_insert_with(|| ChunkedTransfer {
                total_chunks,
                received_chunks: HashMap::new(),
                checksum: checksum.map(|s| s.to_string()),
                plugin_name: plugin_name.to_string(),
                plugin_config: config.clone(),
            });

        transfer.received_chunks.insert(chunk_index, chunk_data);

        info!(
            "Received chunk {}/{} for plugin {}",
            chunk_index + 1,
            total_chunks,
            plugin_name
        );

        // Check if all chunks received
        if transfer.received_chunks.len() == total_chunks as usize {
            info!(
                "All chunks received for plugin {}, assembling file",
                plugin_name
            );

            // Assemble the complete file - first concatenate all base64 chunks, then decode once
            let mut complete_base64 = String::new();
            for i in 0..total_chunks {
                if let Some(chunk) = transfer.received_chunks.get(&i) {
                    // Convert chunk bytes back to string (these are base64 encoded pieces)
                    let chunk_str =
                        String::from_utf8(chunk.clone()).context("Invalid UTF-8 in chunk data")?;
                    complete_base64.push_str(&chunk_str);
                } else {
                    return Err(anyhow!("Missing chunk {} for plugin {}", i, plugin_name));
                }
            }

            // Now decode the complete base64 data
            let complete_data = general_purpose::STANDARD
                .decode(&complete_base64)
                .context("Failed to decode complete base64 data")?;

            // Verify checksum if provided
            if let Some(expected_checksum) = &transfer.checksum {
                self.verify_checksum(&complete_data, expected_checksum, "md5")?;
            }

            let plugin_config = transfer.plugin_config.clone();

            // Remove from transfers map
            transfers.remove(chunk_id);
            drop(transfers); // Release the lock

            // Install the assembled plugin
            self.install_binary_content(plugin_name, &complete_data, plugin_config)
                .await
        } else {
            Ok(serde_json::json!({
                "plugin_name": plugin_name,
                "chunk_id": chunk_id,
                "chunks_received": transfer.received_chunks.len(),
                "total_chunks": total_chunks,
                "status": "chunk_received"
            }))
        }
    }

    async fn install_binary_content(
        &self,
        plugin_name: &str,
        content: &[u8],
        config: PluginConfig,
    ) -> Result<serde_json::Value> {
        use crate::config::AethericConfig;

        // Create plugin directory (expand ~ if needed)
        let install_dir = AethericConfig::expand_path(&self.config.plugins.install_dir);
        let plugin_path = install_dir.join(plugin_name);
        fs::create_dir_all(&plugin_path).await?;

        // Determine file extension based on content type
        let file_name = if self.is_script_content(content) {
            "plugin.sh"
        } else if self.is_binary_content(content) {
            "plugin"
        } else {
            "plugin.bin"
        };

        // Save the binary/script
        let binary_path = plugin_path.join(file_name);
        let mut file = fs::File::create(&binary_path).await?;
        file.write_all(content).await?;
        file.sync_all().await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&binary_path).await?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&binary_path, permissions).await?;
        }

        // Save plugin configuration
        self.save_plugin_config(plugin_name, config).await?;

        // Set status to installed
        self.set_plugin_status(plugin_name, PluginStatus::Installed)
            .await?;

        info!("Plugin {} installed successfully", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "installed",
            "path": plugin_path,
            "binary": binary_path
        }))
    }

    fn verify_checksum(&self, data: &[u8], expected: &str, checksum_type: &str) -> Result<()> {
        let actual = match checksum_type.to_lowercase().as_str() {
            "md5" => format!("{:x}", md5::compute(data)),
            "sha256" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            }
            _ => return Err(anyhow!("Unsupported checksum type: {}", checksum_type)),
        };

        if actual.to_lowercase() != expected.to_lowercase() {
            return Err(anyhow!(
                "Checksum verification failed: expected {}, got {}",
                expected,
                actual
            ));
        }

        Ok(())
    }

    fn is_script_content(&self, content: &[u8]) -> bool {
        content.starts_with(b"#!/")
    }

    fn is_binary_content(&self, content: &[u8]) -> bool {
        // Check for ELF magic number (Linux binaries)
        content.starts_with(&[0x7f, 0x45, 0x4c, 0x46])
    }

    async fn save_plugin_config(&self, plugin_name: &str, config: PluginConfig) -> Result<()> {
        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        fs::create_dir_all(&plugin_path).await?;

        let config_path = plugin_path.join("plugin.toml");
        let config_content = toml::to_string_pretty(&config)?;

        fs::write(&config_path, config_content).await?;

        Ok(())
    }

    async fn get_plugin_config(&self, plugin_name: &str) -> Result<PluginConfig> {
        let config_path = self
            .config
            .plugins
            .install_dir
            .join(plugin_name)
            .join("plugin.toml");

        if !config_path.exists() {
            return Err(anyhow!("Plugin configuration not found"));
        }

        let content = fs::read_to_string(&config_path).await?;
        let config: PluginConfig = toml::from_str(&content)?;

        Ok(config)
    }

    async fn get_plugin_info(&self, plugin_name: &str) -> Result<PluginInfo> {
        let plugin_path = self.config.plugins.install_dir.join(plugin_name);

        if !plugin_path.exists() {
            return Err(anyhow!("Plugin not found: {}", plugin_name));
        }

        let config = self.get_plugin_config(plugin_name).await?;
        let status = self.detect_plugin_status(plugin_name, &config).await;

        // Get install time from directory metadata
        let metadata = fs::metadata(&plugin_path).await?;
        let install_time = metadata
            .created()
            .or_else(|_| metadata.modified())
            .map(|t| format!("{:?}", t))
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(PluginInfo {
            name: plugin_name.to_string(),
            version: config.version.clone(),
            plugin_type: config.plugin_type.clone(),
            status,
            path: plugin_path,
            pid: None, // TODO: Implement PID tracking
            config,
            install_time,
            last_started: None, // TODO: Implement start time tracking
            restart_count: 0,
            last_health_check: None,
            health_check_failures: 0,
            enabled: true,
            maintenance_mode: false,
            maintenance_reason: None,
        })
    }

    async fn detect_plugin_status(&self, plugin_name: &str, config: &PluginConfig) -> PluginStatus {
        match config.plugin_type {
            PluginType::Docker => {
                // Check if Docker container is running
                let output = Command::new("docker")
                    .args([
                        "ps",
                        "--filter",
                        &format!("name={}", plugin_name),
                        "--format",
                        "{{.Names}}",
                    ])
                    .output();

                match output {
                    Ok(out) if out.status.success() => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        if stdout.trim().contains(plugin_name) {
                            PluginStatus::Running
                        } else {
                            PluginStatus::Stopped
                        }
                    }
                    _ => PluginStatus::Stopped,
                }
            }
            PluginType::Binary | PluginType::Script => {
                // Check systemd service status
                let service_name = format!("aetheric-plugin-{}", plugin_name);
                let output = Command::new("systemctl")
                    .args(["is-active", &service_name])
                    .output();

                match output {
                    Ok(out) if out.status.success() => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        match stdout.trim() {
                            "active" => PluginStatus::Running,
                            "inactive" | "failed" => PluginStatus::Stopped,
                            _ => PluginStatus::Installed,
                        }
                    }
                    _ => PluginStatus::Installed,
                }
            }
            PluginType::AptPackage => {
                // Check if systemd service is running (for APT packages that install services)
                let output = Command::new("systemctl")
                    .args(["is-active", plugin_name])
                    .output();

                match output {
                    Ok(out) if out.status.success() => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        match stdout.trim() {
                            "active" => PluginStatus::Running,
                            "inactive" | "failed" => PluginStatus::Stopped,
                            _ => PluginStatus::Installed,
                        }
                    }
                    _ => PluginStatus::Installed,
                }
            }
        }
    }

    async fn set_plugin_status(&self, plugin_name: &str, status: PluginStatus) -> Result<()> {
        // TODO: Implement status persistence
        debug!("Setting plugin {} status to {:?}", plugin_name, status);
        Ok(())
    }

    async fn backup_plugin(&self, plugin_name: &str) -> Result<()> {
        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        let backup_path = self
            .config
            .plugins
            .install_dir
            .join(format!("{}.backup", plugin_name));

        if plugin_path.exists() {
            if backup_path.exists() {
                fs::remove_dir_all(&backup_path).await?;
            }
            self.copy_dir_all(&plugin_path, &backup_path).await?;
        }

        Ok(())
    }

    async fn restore_plugin_backup(&self, plugin_name: &str) -> Result<()> {
        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        let backup_path = self
            .config
            .plugins
            .install_dir
            .join(format!("{}.backup", plugin_name));

        if backup_path.exists() {
            if plugin_path.exists() {
                fs::remove_dir_all(&plugin_path).await?;
            }
            self.copy_dir_all(&backup_path, &plugin_path).await?;
            fs::remove_dir_all(&backup_path).await?;
        }

        Ok(())
    }

    async fn copy_dir_all(&self, src: &Path, dst: &Path) -> Result<()> {
        use std::future::Future;
        use std::pin::Pin;

        fn copy_dir_all_recursive(
            src: PathBuf,
            dst: PathBuf,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(async move {
                fs::create_dir_all(&dst).await?;
                let mut entries = fs::read_dir(&src).await?;

                while let Some(entry) = entries.next_entry().await? {
                    let ty = entry.file_type().await?;
                    if ty.is_dir() {
                        copy_dir_all_recursive(entry.path(), dst.join(entry.file_name())).await?;
                    } else {
                        fs::copy(entry.path(), dst.join(entry.file_name())).await?;
                    }
                }

                Ok(())
            })
        }

        copy_dir_all_recursive(src.to_path_buf(), dst.to_path_buf()).await
    }

    // Plugin lifecycle methods (start/stop)

    async fn start_binary_plugin(
        &self,
        plugin_name: &str,
        info: &PluginInfo,
    ) -> Result<serde_json::Value> {
        // For binary plugins, use systemd service
        let service_name = format!("aetheric-plugin-{}", plugin_name);

        // Ensure systemd service exists
        self.create_systemd_service_for_plugin(plugin_name, info)
            .await?;

        // Start the service
        let output = Command::new("sudo")
            .args(["systemctl", "start", &service_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to start plugin service {}: {}",
                service_name,
                stderr
            ));
        }

        // Enable auto-start if configured
        if info.config.auto_start {
            let _ = Command::new("sudo")
                .args(["systemctl", "enable", &service_name])
                .output();
        }

        info!("Started plugin service: {}", service_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "service_name": service_name,
            "status": "started"
        }))
    }

    async fn stop_binary_plugin(
        &self,
        plugin_name: &str,
        _info: &PluginInfo,
    ) -> Result<serde_json::Value> {
        let service_name = format!("aetheric-plugin-{}", plugin_name);

        let output = Command::new("sudo")
            .args(["systemctl", "stop", &service_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to stop plugin service {}: {}", service_name, stderr);
        }

        info!("Stopped plugin service: {}", service_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "service_name": service_name,
            "status": "stopped"
        }))
    }

    async fn create_systemd_service_for_plugin(
        &self,
        plugin_name: &str,
        info: &PluginInfo,
    ) -> Result<()> {
        let service_name = format!("aetheric-plugin-{}", plugin_name);
        let service_file = format!("/etc/systemd/system/{}.service", service_name);

        // Check if service already exists
        if Path::new(&service_file).exists() {
            return Ok(());
        }

        let binary_path = if info.path.join("plugin").exists() {
            info.path.join("plugin")
        } else if info.path.join("plugin.sh").exists() {
            info.path.join("plugin.sh")
        } else {
            return Err(anyhow!("Plugin binary not found"));
        };

        // Build environment variables string
        let mut env_vars = String::new();
        for (key, value) in &info.config.environment {
            env_vars.push_str(&format!("Environment={}={}\n", key, value));
        }

        // Build command arguments
        let exec_start = if info.config.command_args.is_empty() {
            binary_path.to_string_lossy().to_string()
        } else {
            format!(
                "{} {}",
                binary_path.to_string_lossy(),
                info.config.command_args.join(" ")
            )
        };

        // Create systemd service content
        let service_content = format!(
            r#"[Unit]
Description=Aetheric Edge Plugin: {}
Documentation=Plugin managed by Aetheric Edge
After=network.target aetheric-agent.service
Wants=aetheric-agent.service

[Service]
Type=simple
User=aetheric
Group=aetheric
ExecStart={}
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30

# Environment variables
{}

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Working directory
WorkingDirectory={}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aetheric-plugin-{}

[Install]
WantedBy=multi-user.target
"#,
            info.config.description.as_deref().unwrap_or(&info.name),
            exec_start,
            env_vars,
            info.path.to_string_lossy(),
            info.path.to_string_lossy(),
            plugin_name
        );

        // Write service file
        fs::write(&service_file, service_content).await?;

        // Set proper permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&service_file).await?.permissions();
            permissions.set_mode(0o644);
            fs::set_permissions(&service_file, permissions).await?;
        }

        // Reload systemd
        let output = Command::new("sudo")
            .args(["systemctl", "daemon-reload"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to reload systemd daemon: {}", stderr);
        }

        info!("Created systemd service for plugin: {}", service_name);
        Ok(())
    }

    async fn remove_systemd_service_for_plugin(&self, plugin_name: &str) -> Result<()> {
        let service_name = format!("aetheric-plugin-{}", plugin_name);
        let service_file = format!("/etc/systemd/system/{}.service", service_name);

        // Stop and disable the service
        let _ = Command::new("sudo")
            .args(["systemctl", "stop", &service_name])
            .output();

        let _ = Command::new("sudo")
            .args(["systemctl", "disable", &service_name])
            .output();

        // Remove service file
        if Path::new(&service_file).exists() {
            fs::remove_file(&service_file).await?;

            // Reload systemd
            let output = Command::new("sudo")
                .args(["systemctl", "daemon-reload"])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to reload systemd daemon: {}", stderr);
            }

            info!("Removed systemd service for plugin: {}", service_name);
        }

        Ok(())
    }

    async fn start_docker_plugin(
        &self,
        plugin_name: &str,
        info: &PluginInfo,
    ) -> Result<serde_json::Value> {
        let _cmd = ["run", "-d", "--name", plugin_name];

        // Build the arguments as owned strings first
        let mut args = Vec::new();

        // Add port mappings
        for port in &info.config.ports {
            args.push("-p".to_string());
            args.push(format!("{}:{}", port, port));
        }

        // Add volume mappings
        for volume in &info.config.volumes {
            args.push("-v".to_string());
            args.push(volume.clone());
        }

        // Add environment variables
        for (key, value) in &info.config.environment {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        // Add image name (you should store this in plugin config)
        args.push("plugin_image".to_string()); // This should be stored in plugin config

        // Add command arguments
        args.extend(info.config.command_args.clone());

        // Convert to string references for the command
        let mut final_cmd = vec!["run", "-d", "--name", plugin_name];
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        final_cmd.extend(arg_refs);

        let output = Command::new("docker").args(&final_cmd).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to start Docker plugin: {}", stderr));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        info!(
            "Started Docker plugin {} with container ID {}",
            plugin_name, container_id
        );

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "started",
            "container_id": container_id
        }))
    }

    async fn stop_docker_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        let output = Command::new("docker")
            .args(["stop", plugin_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to stop Docker plugin {}: {}", plugin_name, stderr);
        }

        // Remove the container
        let _ = Command::new("docker").args(["rm", plugin_name]).output();

        info!("Stopped Docker plugin: {}", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "stopped"
        }))
    }

    async fn start_service_plugin(
        &self,
        plugin_name: &str,
        _info: &PluginInfo,
    ) -> Result<serde_json::Value> {
        let output = Command::new("sudo")
            .args(["systemctl", "start", plugin_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to start service {}: {}",
                plugin_name,
                stderr
            ));
        }

        info!("Started service plugin: {}", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "started"
        }))
    }

    async fn stop_service_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        let output = Command::new("sudo")
            .args(["systemctl", "stop", plugin_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to stop service {}: {}", plugin_name, stderr);
        }

        info!("Stopped service plugin: {}", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "stopped"
        }))
    }

    async fn remove_docker_plugin(&self, plugin_name: &str) -> Result<()> {
        // Stop and remove container
        let _ = Command::new("docker").args(["stop", plugin_name]).output();
        let _ = Command::new("docker").args(["rm", plugin_name]).output();

        // Remove image (optional - might want to keep for reinstall)
        // let _ = Command::new("docker").args(&["rmi", &image_name]).output();

        Ok(())
    }

    async fn remove_apt_package(&self, plugin_name: &str) -> Result<()> {
        // Get package name from config
        if let Ok(_config) = self.get_plugin_config(plugin_name).await {
            // Extract package name from config or use plugin name
            let package_name = plugin_name; // This should be stored in plugin config

            let output = Command::new("sudo")
                .args(["apt", "remove", "-y", package_name])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to remove APT package {}: {}", package_name, stderr);
            }
        }

        Ok(())
    }

    // Health monitoring and management methods

    pub async fn enable_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Enabling plugin: {}", plugin_name);

        let plugin_dir = self.config.plugins.install_dir.join(plugin_name);
        if !plugin_dir.exists() {
            return Err(anyhow!("Plugin not found: {}", plugin_name));
        }

        let config_path = plugin_dir.join("plugin.toml");
        if let Ok(mut plugin_info) = self.load_plugin_info(&config_path).await {
            plugin_info.enabled = true;
            plugin_info.maintenance_mode = false;
            plugin_info.maintenance_reason = None;
            self.save_plugin_info(&config_path, &plugin_info).await?;

            // If plugin was previously running, restart it
            if matches!(
                plugin_info.status,
                PluginStatus::Running | PluginStatus::Stopped
            ) {
                let _ = self.start_plugin(plugin_name).await;
            }
        }

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "enabled",
            "message": "Plugin enabled successfully"
        }))
    }

    pub async fn disable_plugin(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Disabling plugin: {}", plugin_name);

        let plugin_dir = self.config.plugins.install_dir.join(plugin_name);
        if !plugin_dir.exists() {
            return Err(anyhow!("Plugin not found: {}", plugin_name));
        }

        // Stop the plugin first
        let _ = self.stop_plugin(plugin_name).await;

        let config_path = plugin_dir.join("plugin.toml");
        if let Ok(mut plugin_info) = self.load_plugin_info(&config_path).await {
            plugin_info.enabled = false;
            plugin_info.status = PluginStatus::Disabled;
            self.save_plugin_info(&config_path, &plugin_info).await?;
        }

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "disabled",
            "message": "Plugin disabled successfully"
        }))
    }

    pub async fn set_plugin_maintenance(
        &self,
        plugin_name: &str,
        maintenance_mode: bool,
        reason: Option<String>,
    ) -> Result<serde_json::Value> {
        info!(
            "Setting maintenance mode for plugin {}: {} - {}",
            plugin_name,
            maintenance_mode,
            reason.as_deref().unwrap_or("No reason")
        );

        let plugin_dir = self.config.plugins.install_dir.join(plugin_name);
        if !plugin_dir.exists() {
            return Err(anyhow!("Plugin not found: {}", plugin_name));
        }

        let config_path = plugin_dir.join("plugin.toml");
        if let Ok(mut plugin_info) = self.load_plugin_info(&config_path).await {
            plugin_info.maintenance_mode = maintenance_mode;
            plugin_info.maintenance_reason = reason.clone();

            if maintenance_mode {
                plugin_info.status = PluginStatus::Maintenance;
                // Stop the plugin when entering maintenance mode
                let _ = self.stop_plugin(plugin_name).await;
            } else {
                // If exiting maintenance mode and plugin is enabled, restart it
                if plugin_info.enabled {
                    let _ = self.start_plugin(plugin_name).await;
                }
            }

            self.save_plugin_info(&config_path, &plugin_info).await?;
        }

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "maintenance_mode": maintenance_mode,
            "reason": reason,
            "message": format!("Plugin maintenance mode {}", if maintenance_mode { "enabled" } else { "disabled" })
        }))
    }

    pub async fn check_plugin_health(&self, plugin_name: &str) -> Result<PluginHealthStatus> {
        let plugin_dir = self.config.plugins.install_dir.join(plugin_name);
        let config_path = plugin_dir.join("plugin.toml");

        let plugin_info = self
            .load_plugin_info(&config_path)
            .await
            .with_context(|| format!("Failed to load plugin info for: {}", plugin_name))?;

        let (cpu_usage, memory_usage) = self.get_plugin_resource_usage(&plugin_info).await;
        let uptime = self.get_plugin_uptime(&plugin_info).await;

        Ok(PluginHealthStatus {
            plugin_name: plugin_name.to_string(),
            status: plugin_info.status.clone(),
            uptime_seconds: uptime,
            restart_count: plugin_info.restart_count,
            health_check_failures: plugin_info.health_check_failures,
            last_health_check: chrono::Utc::now().to_rfc3339(),
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            enabled: plugin_info.enabled,
            maintenance_mode: plugin_info.maintenance_mode,
        })
    }

    pub async fn monitor_all_plugins_health(&self) -> Result<Vec<PluginHealthStatus>> {
        let mut health_statuses = Vec::new();

        if !self.config.plugins.install_dir.exists() {
            return Ok(health_statuses);
        }

        let mut entries = fs::read_dir(&self.config.plugins.install_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let plugin_name = entry.file_name().to_string_lossy().to_string();

                match self.check_plugin_health(&plugin_name).await {
                    Ok(health_status) => {
                        health_statuses.push(health_status);

                        // Check if plugin needs restart
                        let _ = self.handle_unhealthy_plugin(&plugin_name).await;
                    }
                    Err(e) => {
                        warn!("Failed to check health for plugin {}: {}", plugin_name, e);
                    }
                }
            }
        }

        Ok(health_statuses)
    }

    async fn handle_unhealthy_plugin(&self, plugin_name: &str) -> Result<()> {
        let plugin_dir = self.config.plugins.install_dir.join(plugin_name);
        let config_path = plugin_dir.join("plugin.toml");

        let mut plugin_info = self.load_plugin_info(&config_path).await?;

        // Skip if plugin is disabled or in maintenance mode
        if !plugin_info.enabled || plugin_info.maintenance_mode {
            return Ok(());
        }

        let is_unhealthy = self.is_plugin_unhealthy(&plugin_info).await?;

        if is_unhealthy {
            plugin_info.health_check_failures += 1;

            // Restart logic with maximum retry attempts
            const MAX_RESTART_ATTEMPTS: u32 = 3;
            const MAX_HEALTH_FAILURES: u32 = 3;

            if plugin_info.health_check_failures >= MAX_HEALTH_FAILURES {
                if plugin_info.restart_count < MAX_RESTART_ATTEMPTS {
                    info!(
                        "Restarting unhealthy plugin: {} (attempt {}/{})",
                        plugin_name,
                        plugin_info.restart_count + 1,
                        MAX_RESTART_ATTEMPTS
                    );

                    plugin_info.restart_count += 1;
                    plugin_info.health_check_failures = 0;
                    plugin_info.status = PluginStatus::Restarting;

                    self.save_plugin_info(&config_path, &plugin_info).await?;

                    // Stop and start the plugin
                    let _ = self.stop_plugin(plugin_name).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    let _ = self.start_plugin(plugin_name).await;
                } else {
                    warn!(
                        "Plugin {} exceeded maximum restart attempts, marking as failed",
                        plugin_name
                    );
                    plugin_info.status = PluginStatus::Failed;
                    plugin_info.enabled = false;
                    self.save_plugin_info(&config_path, &plugin_info).await?;
                }
            }
        } else {
            // Reset failure count if plugin is healthy
            if plugin_info.health_check_failures > 0 {
                plugin_info.health_check_failures = 0;
                self.save_plugin_info(&config_path, &plugin_info).await?;
            }
        }

        Ok(())
    }

    async fn is_plugin_unhealthy(&self, plugin_info: &PluginInfo) -> Result<bool> {
        match plugin_info.plugin_type {
            PluginType::Binary | PluginType::Script => {
                self.is_systemd_service_unhealthy(plugin_info).await
            }
            PluginType::Docker => self.is_docker_container_unhealthy(plugin_info).await,
            PluginType::AptPackage => {
                // APT packages are typically system services
                self.is_systemd_service_unhealthy(plugin_info).await
            }
        }
    }

    async fn is_systemd_service_unhealthy(&self, plugin_info: &PluginInfo) -> Result<bool> {
        let service_name = format!("aetheric-plugin-{}", plugin_info.name);

        let output = Command::new("systemctl")
            .args(["is-active", &service_name])
            .output()?;

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Service is unhealthy if it's not active or if it's failed
        Ok(status != "active")
    }

    async fn is_docker_container_unhealthy(&self, plugin_info: &PluginInfo) -> Result<bool> {
        let container_name = format!("aetheric-plugin-{}", plugin_info.name);

        let output = Command::new("docker")
            .args(["inspect", "--format", "{{.State.Status}}", &container_name])
            .output()?;

        if !output.status.success() {
            return Ok(true); // Container doesn't exist or error occurred
        }

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Container is unhealthy if it's not running
        Ok(status != "running")
    }

    async fn get_plugin_resource_usage(&self, plugin_info: &PluginInfo) -> (f32, u64) {
        match plugin_info.plugin_type {
            PluginType::Binary | PluginType::Script => {
                self.get_systemd_service_resources(plugin_info).await
            }
            PluginType::Docker => self.get_docker_container_resources(plugin_info).await,
            PluginType::AptPackage => self.get_systemd_service_resources(plugin_info).await,
        }
    }

    async fn get_systemd_service_resources(&self, plugin_info: &PluginInfo) -> (f32, u64) {
        let service_name = format!("aetheric-plugin-{}", plugin_info.name);

        // Get CPU usage
        let cpu_usage = match Command::new("systemctl")
            .args(["show", &service_name, "--property=CPUUsageNSec"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = output_str.lines().find(|l| l.starts_with("CPUUsageNSec=")) {
                    if let Some(value) = line.split('=').nth(1) {
                        value.parse::<f32>().unwrap_or(0.0) / 1_000_000_000.0 // Convert nanoseconds to seconds
                    } else {
                        0.0
                    }
                } else {
                    0.0
                }
            }
            Err(_) => 0.0,
        };

        // Get memory usage
        let memory_usage = match Command::new("systemctl")
            .args(["show", &service_name, "--property=MemoryCurrent"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = output_str.lines().find(|l| l.starts_with("MemoryCurrent=")) {
                    if let Some(value) = line.split('=').nth(1) {
                        value.parse::<u64>().unwrap_or(0) / 1024 / 1024 // Convert bytes to MB
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            Err(_) => 0,
        };

        (cpu_usage, memory_usage)
    }

    async fn get_docker_container_resources(&self, plugin_info: &PluginInfo) -> (f32, u64) {
        let container_name = format!("aetheric-plugin-{}", plugin_info.name);

        // Get resource stats
        let output = match Command::new("docker")
            .args([
                "stats",
                "--no-stream",
                "--format",
                "{{.CPUPerc}},{{.MemUsage}}",
                &container_name,
            ])
            .output()
        {
            Ok(output) => output,
            Err(_) => return (0.0, 0),
        };

        if !output.status.success() {
            return (0.0, 0);
        }

        let stats = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stats.trim().split(',').collect();

        if parts.len() != 2 {
            return (0.0, 0);
        }

        // Parse CPU percentage
        let cpu_usage = parts[0].trim_end_matches('%').parse::<f32>().unwrap_or(0.0);

        // Parse memory usage (format: "used / total")
        let memory_usage = if let Some(used_part) = parts[1].split('/').next() {
            let used_str = used_part.trim();
            if used_str.ends_with("MiB") {
                used_str.trim_end_matches("MiB").parse::<u64>().unwrap_or(0)
            } else if used_str.ends_with("GiB") {
                used_str.trim_end_matches("GiB").parse::<u64>().unwrap_or(0) * 1024
            } else {
                0
            }
        } else {
            0
        };

        (cpu_usage, memory_usage)
    }

    async fn get_plugin_uptime(&self, plugin_info: &PluginInfo) -> u64 {
        if let Some(last_started) = &plugin_info.last_started {
            if let Ok(start_time) = chrono::DateTime::parse_from_rfc3339(last_started) {
                let now = chrono::Utc::now();
                let duration = now.signed_duration_since(start_time.with_timezone(&chrono::Utc));
                return duration.num_seconds().max(0) as u64;
            }
        }
        0
    }

    async fn load_plugin_info(&self, config_path: &std::path::Path) -> Result<PluginInfo> {
        if !config_path.exists() {
            return Err(anyhow!("Plugin config file not found"));
        }

        let content = fs::read_to_string(config_path).await?;
        let plugin_info: PluginInfo = toml::from_str(&content)?;
        Ok(plugin_info)
    }

    async fn save_plugin_info(
        &self,
        config_path: &std::path::Path,
        plugin_info: &PluginInfo,
    ) -> Result<()> {
        let content = toml::to_string_pretty(plugin_info)?;
        fs::write(config_path, content).await?;
        Ok(())
    }
}
