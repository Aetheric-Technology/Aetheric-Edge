use crate::agent::plugin_manager::{PluginManager, PluginSource as PMPluginSource, PluginConfig as PMPluginConfig};
use crate::agent::ssh_tunnel::{SshTunnelManager, SshCommand};
use crate::config::AethericConfig;
use crate::mqtt::messages::*;
use anyhow::Result;
use base64::Engine;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct CommandHandler {
    config: Arc<AethericConfig>,
    plugin_manager: PluginManager,
    ssh_tunnel_manager: Arc<SshTunnelManager>,
}

impl CommandHandler {
    pub fn new(config: Arc<AethericConfig>, ssh_tunnel_manager: Arc<SshTunnelManager>) -> Self {
        let plugin_manager = PluginManager::new(config.clone());
        Self { config, plugin_manager, ssh_tunnel_manager }
    }

    pub async fn handle_command(&self, command: CommandMessage) -> CommandResponse {
        debug!("Handling command: {:?}", command.command);

        let result = match &command.command {
            CommandType::Health => self.handle_health_command().await,
            
            // Plugin management commands
            CommandType::Install { plugin_name, source, config } => {
                self.handle_plugin_install_command(plugin_name, source, config.as_ref()).await
            }
            CommandType::Update { plugin_name, source, config } => {
                self.handle_plugin_update_command(plugin_name, source, config.as_ref()).await
            }
            CommandType::Remove { plugin_name } => {
                self.handle_plugin_remove_command(plugin_name).await
            }
            CommandType::Start { plugin_name } => {
                self.handle_plugin_start_command(plugin_name).await
            }
            CommandType::Stop { plugin_name } => {
                self.handle_plugin_stop_command(plugin_name).await
            }
            CommandType::Restart { plugin_name } => {
                self.handle_plugin_restart_command(plugin_name).await
            }
            CommandType::Status { plugin_name } => {
                self.handle_plugin_status_command(plugin_name.as_deref()).await
            }
            CommandType::List => {
                self.handle_plugin_list_command().await
            }
            
            // System management commands
            CommandType::OtaUpdate { version, url, checksum } => {
                self.handle_ota_update_command(version, url, checksum.as_deref()).await
            }
            CommandType::SshConnect { session_id, target_host, target_port, duration_minutes } => {
                self.handle_ssh_connect_command(session_id, target_host.clone(), *target_port, *duration_minutes).await
            }
            CommandType::SshDisconnect { session_id } => {
                self.handle_ssh_disconnect_command(session_id).await
            }
            CommandType::SshData { session_id, data, direction } => {
                self.handle_ssh_data_command(session_id, data, direction.clone()).await
            }
            CommandType::SshHeartbeat { session_id } => {
                self.handle_ssh_heartbeat_command(session_id).await
            }
            CommandType::EnablePlugin { plugin_name } => {
                self.handle_enable_plugin_command(plugin_name).await
            }
            CommandType::DisablePlugin { plugin_name } => {
                self.handle_disable_plugin_command(plugin_name).await
            }
            CommandType::SetPluginMaintenance { plugin_name, maintenance_mode, reason } => {
                self.handle_set_plugin_maintenance_command(plugin_name, *maintenance_mode, reason.clone()).await
            }
            CommandType::SystemRestart => self.handle_system_restart_command().await,
        };

        match result {
            Ok(result) => CommandResponse::new(
                command.id,
                CommandStatus::Success,
                "Command executed successfully".to_string(),
            ).with_result(result),
            Err(e) => CommandResponse::new(
                command.id,
                CommandStatus::Failed,
                format!("Command failed: {}", e),
            ),
        }
    }

    async fn handle_health_command(&self) -> Result<serde_json::Value> {
        info!("Processing health command");
        
        let health_data = serde_json::json!({
            "gateway_id": self.config.gateway.id,
            "uptime": self.get_uptime().await,
            "memory_usage": self.get_memory_usage().await,
            "cpu_usage": self.get_cpu_usage().await,
            "disk_usage": self.get_disk_usage().await,
            "network_status": "connected"
        });

        Ok(health_data)
    }

    async fn handle_install_command(
        &self,
        plugin_name: &str,
        source: &InstallSource,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin: {}", plugin_name);

        match source {
            InstallSource::Url { url, checksum } => {
                self.install_from_url(plugin_name, url, checksum.as_deref()).await
            }
            InstallSource::Docker { image, tag } => {
                self.install_docker_container(plugin_name, image, tag.as_deref()).await
            }
            InstallSource::Local { path } => {
                self.install_from_local_path(plugin_name, path).await
            }
        }
    }

    async fn handle_remove_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Removing plugin: {}", plugin_name);

        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        
        if plugin_path.exists() {
            fs::remove_dir_all(&plugin_path).await?;
            info!("Plugin {} removed successfully", plugin_name);
        } else {
            warn!("Plugin {} not found", plugin_name);
        }

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "removed"
        }))
    }

    async fn handle_ota_update_command(
        &self,
        version: &str,
        url: &str,
        checksum: Option<&str>,
    ) -> Result<serde_json::Value> {
        info!("Starting OTA update to version: {}", version);

        // Download the update package
        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        let content = response.bytes().await?;

        // Verify checksum if provided
        if let Some(expected_checksum) = checksum {
            let actual_checksum = format!("{:x}", md5::compute(&content));
            if actual_checksum != expected_checksum {
                anyhow::bail!("Checksum verification failed");
            }
        }

        // Save the update package to temp directory
        let temp_path = self.config.plugins.temp_dir.join("ota_update.bin");
        fs::create_dir_all(&self.config.plugins.temp_dir).await?;
        
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&content).await?;
        file.sync_all().await?;

        info!("OTA update package downloaded and ready for installation");

        Ok(serde_json::json!({
            "version": version,
            "status": "ready_for_install",
            "package_path": temp_path
        }))
    }

    async fn handle_ssh_connect_command(
        &self,
        session_id: &str,
        target_host: Option<String>,
        target_port: Option<u16>,
        duration_minutes: Option<u32>,
    ) -> Result<serde_json::Value> {
        if !self.config.ssh.enabled {
            anyhow::bail!("SSH functionality is disabled");
        }

        info!("Setting up SSH connection for session: {}", session_id);

        let ssh_command = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host,
            target_port,
            duration_minutes,
        };

        let response = self.ssh_tunnel_manager.handle_ssh_command(ssh_command).await?;
        
        Ok(serde_json::json!({
            "session_id": response.session_id,
            "status": response.status,
            "message": response.message,
            "local_port": response.local_port
        }))
    }

    async fn handle_ssh_disconnect_command(&self, session_id: &str) -> Result<serde_json::Value> {
        info!("Disconnecting SSH session: {}", session_id);

        let ssh_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let response = self.ssh_tunnel_manager.handle_ssh_command(ssh_command).await?;
        
        Ok(serde_json::json!({
            "session_id": response.session_id,
            "status": response.status,
            "message": response.message
        }))
    }

    async fn handle_ssh_data_command(
        &self,
        session_id: &str,
        data: &str,
        direction: SshDataDirection,
    ) -> Result<serde_json::Value> {
        debug!("Handling SSH data for session: {}", session_id);

        let ssh_direction = match direction {
            SshDataDirection::Up => crate::agent::ssh_tunnel::SshDataDirection::Up,
            SshDataDirection::Down => crate::agent::ssh_tunnel::SshDataDirection::Down,
        };

        let ssh_command = SshCommand::Data {
            session_id: session_id.to_string(),
            data: data.to_string(),
            direction: ssh_direction,
        };

        let response = self.ssh_tunnel_manager.handle_ssh_command(ssh_command).await?;
        
        Ok(serde_json::json!({
            "session_id": response.session_id,
            "status": response.status,
            "message": response.message
        }))
    }

    async fn handle_ssh_heartbeat_command(&self, session_id: &str) -> Result<serde_json::Value> {
        debug!("Handling SSH heartbeat for session: {}", session_id);

        let ssh_command = SshCommand::Heartbeat {
            session_id: session_id.to_string(),
        };

        let response = self.ssh_tunnel_manager.handle_ssh_command(ssh_command).await?;
        
        Ok(serde_json::json!({
            "session_id": response.session_id,
            "status": response.status,
            "message": response.message,
            "local_port": response.local_port
        }))
    }

    // New plugin management command handlers
    
    async fn handle_plugin_install_command(
        &self,
        plugin_name: &str,
        source: &PluginSource,
        config: Option<&PluginConfig>,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin: {} from source: {:?}", plugin_name, source);

        // Create default config if none provided
        let plugin_config = match config {
            Some(cfg) => cfg.clone(),
            None => self.create_default_plugin_config(plugin_name, source).await?,
        };

        let pm_source = self.convert_plugin_source(source)?;
        let pm_config = self.convert_plugin_config(&plugin_config)?;
        self.plugin_manager.install_plugin(plugin_name, &pm_source, pm_config).await
    }

    async fn handle_plugin_update_command(
        &self,
        plugin_name: &str,
        source: &PluginSource,
        config: Option<&PluginConfig>,
    ) -> Result<serde_json::Value> {
        info!("Updating plugin: {}", plugin_name);
        let pm_source = self.convert_plugin_source(source)?;
        let pm_config = match config {
            Some(cfg) => Some(self.convert_plugin_config(cfg)?),
            None => None,
        };
        self.plugin_manager.update_plugin(plugin_name, &pm_source, pm_config).await
    }

    async fn handle_plugin_remove_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Removing plugin: {}", plugin_name);
        self.plugin_manager.remove_plugin(plugin_name).await
    }

    async fn handle_plugin_start_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Starting plugin: {}", plugin_name);
        self.plugin_manager.start_plugin(plugin_name).await
    }

    async fn handle_plugin_stop_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Stopping plugin: {}", plugin_name);
        self.plugin_manager.stop_plugin(plugin_name).await
    }

    async fn handle_plugin_restart_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Restarting plugin: {}", plugin_name);
        self.plugin_manager.restart_plugin(plugin_name).await
    }

    async fn handle_plugin_status_command(&self, plugin_name: Option<&str>) -> Result<serde_json::Value> {
        match plugin_name {
            Some(name) => {
                info!("Getting status for plugin: {}", name);
                self.plugin_manager.get_plugin_status(name).await
            }
            None => {
                info!("Getting status for all plugins");
                self.plugin_manager.list_plugins().await
            }
        }
    }

    async fn handle_plugin_list_command(&self) -> Result<serde_json::Value> {
        info!("Listing all plugins");
        self.plugin_manager.list_plugins().await
    }

    async fn create_default_plugin_config(
        &self,
        plugin_name: &str,
        source: &PluginSource,
    ) -> Result<PluginConfig> {
        let plugin_type = match source {
            PluginSource::Docker { .. } => PluginType::Docker,
            PluginSource::AptPackage { .. } => PluginType::AptPackage,
            PluginSource::Base64 { data, .. } => {
                // Try to detect if it's a script or binary
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) {
                    if decoded.starts_with(b"#!/") {
                        PluginType::Script
                    } else {
                        PluginType::Binary
                    }
                } else {
                    PluginType::Binary
                }
            }
            _ => PluginType::Binary,
        };

        Ok(PluginConfig {
            name: plugin_name.to_string(),
            version: "1.0.0".to_string(),
            description: Some(format!("Auto-generated plugin: {}", plugin_name)),
            plugin_type,
            auto_start: false,
            environment: HashMap::new(),
            dependencies: Vec::new(),
            ports: Vec::new(),
            volumes: Vec::new(),
            command_args: Vec::new(),
        })
    }

    fn convert_plugin_source(&self, source: &PluginSource) -> Result<PMPluginSource> {
        let pm_source = match source {
            PluginSource::Url { url, checksum, checksum_type } => PMPluginSource::Url {
                url: url.clone(),
                checksum: checksum.clone(),
                checksum_type: checksum_type.clone(),
            },
            PluginSource::Base64 { data, checksum, checksum_type } => PMPluginSource::Base64 {
                data: data.clone(),
                checksum: checksum.clone(),
                checksum_type: checksum_type.clone(),
            },
            PluginSource::AptPackage { package, version, repository } => PMPluginSource::AptPackage {
                package: package.clone(),
                version: version.clone(),
                repository: repository.clone(),
            },
            PluginSource::Docker { image, tag, registry } => PMPluginSource::Docker {
                image: image.clone(),
                tag: tag.clone(),
                registry: registry.clone(),
            },
            PluginSource::Chunked { chunk_id, total_chunks, chunk_index, data, checksum } => PMPluginSource::Chunked {
                chunk_id: chunk_id.clone(),
                total_chunks: *total_chunks,
                chunk_index: *chunk_index,
                data: data.clone(),
                checksum: checksum.clone(),
            },
            PluginSource::Local { path } => PMPluginSource::Local {
                path: path.clone(),
            },
        };
        Ok(pm_source)
    }

    fn convert_plugin_config(&self, config: &PluginConfig) -> Result<PMPluginConfig> {
        use crate::agent::plugin_manager::PluginType as PMPluginType;
        
        let pm_plugin_type = match config.plugin_type {
            PluginType::Binary => PMPluginType::Binary,
            PluginType::Docker => PMPluginType::Docker,
            PluginType::AptPackage => PMPluginType::AptPackage,
            PluginType::Script => PMPluginType::Script,
        };

        Ok(PMPluginConfig {
            name: config.name.clone(),
            version: config.version.clone(),
            description: config.description.clone(),
            plugin_type: pm_plugin_type,
            auto_start: config.auto_start,
            environment: config.environment.clone(),
            dependencies: config.dependencies.clone(),
            ports: config.ports.clone(),
            volumes: config.volumes.clone(),
            command_args: config.command_args.clone(),
        })
    }

    async fn handle_system_restart_command(&self) -> Result<serde_json::Value> {
        info!("Restarting system");

        // Schedule a restart after a short delay to allow response to be sent
        tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if let Err(e) = Command::new("sudo").args(&["reboot"]).output() {
                error!("Failed to restart system: {}", e);
            }
        });

        Ok(serde_json::json!({
            "status": "restart_scheduled",
            "delay_seconds": 5
        }))
    }

    async fn handle_enable_plugin_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Enabling plugin: {}", plugin_name);
        self.plugin_manager.enable_plugin(plugin_name).await
    }

    async fn handle_disable_plugin_command(&self, plugin_name: &str) -> Result<serde_json::Value> {
        info!("Disabling plugin: {}", plugin_name);
        self.plugin_manager.disable_plugin(plugin_name).await
    }

    async fn handle_set_plugin_maintenance_command(&self, plugin_name: &str, maintenance_mode: bool, reason: Option<String>) -> Result<serde_json::Value> {
        info!("Setting maintenance mode for plugin {}: {}", plugin_name, maintenance_mode);
        self.plugin_manager.set_plugin_maintenance(plugin_name, maintenance_mode, reason).await
    }

    async fn install_from_url(
        &self,
        plugin_name: &str,
        url: &str,
        checksum: Option<&str>,
    ) -> Result<serde_json::Value> {
        info!("Downloading plugin from URL: {}", url);

        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        let content = response.bytes().await?;

        // Verify checksum if provided
        if let Some(expected_checksum) = checksum {
            let actual_checksum = format!("{:x}", md5::compute(&content));
            if actual_checksum != expected_checksum {
                anyhow::bail!("Checksum verification failed");
            }
        }

        // Create plugin directory
        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        fs::create_dir_all(&plugin_path).await?;

        // Save the binary
        let binary_path = plugin_path.join("plugin");
        let mut file = fs::File::create(&binary_path).await?;
        file.write_all(&content).await?;
        file.sync_all().await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&binary_path).await?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&binary_path, permissions).await?;
        }

        info!("Plugin {} installed successfully", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "installed",
            "path": plugin_path
        }))
    }

    async fn install_docker_container(
        &self,
        plugin_name: &str,
        image: &str,
        tag: Option<&str>,
    ) -> Result<serde_json::Value> {
        if !self.config.plugins.docker_enabled {
            anyhow::bail!("Docker functionality is disabled");
        }

        let full_image = match tag {
            Some(t) => format!("{}:{}", image, t),
            None => format!("{}:latest", image),
        };

        info!("Installing Docker container: {}", full_image);

        // Pull the Docker image
        let output = Command::new("docker")
            .args(&["pull", &full_image])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to pull Docker image: {}", stderr);
        }

        // Create a container configuration
        let config_path = self.config.plugins.install_dir.join(format!("{}.json", plugin_name));
        let config = serde_json::json!({
            "plugin_name": plugin_name,
            "type": "docker",
            "image": full_image,
            "installed_at": chrono::Utc::now().to_rfc3339()
        });

        let mut file = fs::File::create(&config_path).await?;
        file.write_all(serde_json::to_string_pretty(&config)?.as_bytes()).await?;

        info!("Docker plugin {} installed successfully", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "installed",
            "type": "docker",
            "image": full_image
        }))
    }

    async fn install_from_local_path(
        &self,
        plugin_name: &str,
        path: &str,
    ) -> Result<serde_json::Value> {
        info!("Installing plugin from local path: {}", path);

        let source_path = std::path::Path::new(path);
        if !source_path.exists() {
            anyhow::bail!("Source path does not exist: {}", path);
        }

        let plugin_path = self.config.plugins.install_dir.join(plugin_name);
        fs::create_dir_all(&plugin_path).await?;

        // Copy the file
        let target_path = plugin_path.join("plugin");
        fs::copy(source_path, &target_path).await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&target_path).await?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&target_path, permissions).await?;
        }

        info!("Plugin {} installed from local path", plugin_name);

        Ok(serde_json::json!({
            "plugin_name": plugin_name,
            "status": "installed",
            "source": "local",
            "path": plugin_path
        }))
    }

    async fn get_uptime(&self) -> u64 {
        // Simple uptime implementation - in a real system, you'd read from /proc/uptime
        match fs::read_to_string("/proc/uptime").await {
            Ok(content) => {
                content.split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|f| f as u64)
                    .unwrap_or(0)
            }
            Err(_) => 0,
        }
    }

    async fn get_memory_usage(&self) -> u64 {
        // Simple memory usage - in a real system, you'd parse /proc/meminfo
        match fs::read_to_string("/proc/meminfo").await {
            Ok(content) => {
                let lines: Vec<&str> = content.lines().collect();
                let total = lines.iter()
                    .find(|line| line.starts_with("MemTotal:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let available = lines.iter()
                    .find(|line| line.starts_with("MemAvailable:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                (total - available) / 1024 // Convert to MB
            }
            Err(_) => 0,
        }
    }

    async fn get_cpu_usage(&self) -> f32 {
        // Simplified CPU usage - in a real system, you'd calculate this properly
        0.0
    }

    async fn get_disk_usage(&self) -> HashMap<String, u64> {
        // Simplified disk usage - in a real system, you'd use statvfs or similar
        HashMap::new()
    }
}