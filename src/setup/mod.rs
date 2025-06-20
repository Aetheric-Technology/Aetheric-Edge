use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

use crate::certs::CertificateManager;
use crate::config::AethericConfig;

mod service_simple;
pub use service_simple::{MqttBrokerManager, PlatformPaths, ServiceManager};

/// Setup and configuration management
pub struct SetupManager {
    config_dir: PathBuf,
    data_dir: PathBuf,
    cert_manager: CertificateManager,
}

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub interactive: bool,
    pub auto: bool,
    pub force: bool,
    pub skip_services: bool,
}

#[derive(Debug, Clone)]
pub struct SetupConfig {
    pub gateway_id: String,
    pub gateway_name: Option<String>,
    pub gateway_location: Option<String>,
    pub gateway_description: Option<String>,
    pub mqtt_remote_host: String,
    pub mqtt_remote_port: u16,
    pub mqtt_remote_username: Option<String>,
    pub mqtt_remote_password: Option<String>,
    pub mqtt_remote_tls: bool,
    pub mqtt_local_username: String,
    pub mqtt_local_password: String,
    pub health_report_interval: u32,
    pub ssh_enabled: bool,
    pub ssh_port: u16,
    pub plugins_docker_enabled: bool,
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            gateway_id: format!(
                "aetheric-{}",
                uuid::Uuid::new_v4().to_string()[..8].to_lowercase()
            ),
            gateway_name: Some("Aetheric Edge Gateway".to_string()),
            gateway_location: None,
            gateway_description: Some(
                "Edge computing gateway managed by Aetheric Edge".to_string(),
            ),
            mqtt_remote_host: "your-cloud-mqtt-broker.com".to_string(),
            mqtt_remote_port: 8883,
            mqtt_remote_username: None,
            mqtt_remote_password: None,
            mqtt_remote_tls: true,
            mqtt_local_username: "aetheric".to_string(),
            mqtt_local_password: generate_password(),
            health_report_interval: 60,
            ssh_enabled: true,
            ssh_port: 22,
            plugins_docker_enabled: true,
        }
    }
}

impl SetupManager {
    pub fn new() -> Result<Self> {
        let config_dir = PlatformPaths::config_dir();
        let data_dir = PlatformPaths::data_dir();
        let cert_manager = CertificateManager::new(data_dir.join("certs"));

        Ok(Self {
            config_dir,
            data_dir,
            cert_manager,
        })
    }

    pub async fn run_setup(&self, options: SetupOptions) -> Result<()> {
        info!("Starting Aetheric Edge setup...");

        // Check if already configured
        if !options.force && self.is_configured()? {
            if options.interactive {
                if !self.prompt_reconfigure()? {
                    info!("Setup cancelled - already configured");
                    return Ok(());
                }
            } else if !options.auto {
                warn!("System already configured. Use --force to reconfigure.");
                return Ok(());
            }
        }

        // Check permissions
        self.check_permissions()?;

        // Create directories if they don't exist
        self.ensure_directories()?;

        // Get configuration
        let config = if options.interactive {
            self.interactive_setup().await?
        } else {
            self.automatic_setup().await?
        };

        // Generate certificates
        self.generate_certificates(&config).await?;

        // Configure local MQTT broker
        self.configure_local_mqtt(&config).await?;

        // Create Aetheric configuration
        self.create_aetheric_config(&config).await?;

        // Configure MQTT bridge (local to remote)
        self.configure_mqtt_bridge(&config).await?;

        // Configure sudo access for aetheric user
        self.configure_sudo_access().await?;

        // Set up systemd services
        if !options.skip_services {
            self.setup_services().await?;
        }

        // Final verification
        self.verify_setup().await?;

        info!("🎉 Aetheric Edge setup completed successfully!");
        self.print_next_steps(&options)?;

        Ok(())
    }

    fn is_configured(&self) -> Result<bool> {
        let config_file = self.config_dir.join("aetheric.toml");
        let mqtt_passwd = self.config_dir.join("mosquitto.passwd");

        Ok(config_file.exists() && mqtt_passwd.exists())
    }

    fn prompt_reconfigure(&self) -> Result<bool> {
        print!("Aetheric Edge appears to be already configured. Reconfigure? [y/N]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        Ok(input.trim().to_lowercase().starts_with('y'))
    }

    fn check_permissions(&self) -> Result<()> {
        // Home directory setup doesn't require elevated privileges
        // Only service installation requires elevated privileges
        Ok(())
    }

    fn ensure_directories(&self) -> Result<()> {
        let log_dir = PlatformPaths::log_dir();
        let dirs = [
            &self.config_dir,
            &self.data_dir,
            &self.data_dir.join("certs"),
            &self.data_dir.join("mosquitto"),
            &self.data_dir.join("plugins"),
            &self.data_dir.join("temp"),
            &log_dir,
        ];

        for dir in &dirs {
            if !dir.exists() {
                fs::create_dir_all(dir)
                    .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
                info!("Created directory: {}", dir.display());
            }
        }

        Ok(())
    }

    async fn interactive_setup(&self) -> Result<SetupConfig> {
        println!("\n🔧 Aetheric Edge Interactive Setup");
        println!("==================================");

        let mut config = SetupConfig::default();

        // Gateway configuration
        println!("\n📡 Gateway Configuration");
        config.gateway_id =
            self.prompt_with_default("Gateway ID", &config.gateway_id, |s| !s.trim().is_empty())?;

        config.gateway_name = Some(self.prompt_with_default(
            "Gateway Name",
            config.gateway_name.as_deref().unwrap_or(""),
            |_| true,
        )?);

        config.gateway_location =
            Some(self.prompt_with_default("Gateway Location (optional)", "", |_| true)?)
                .filter(|s| !s.is_empty());

        config.gateway_description = Some(self.prompt_with_default(
            "Gateway Description (optional)",
            config.gateway_description.as_deref().unwrap_or(""),
            |_| true,
        )?)
        .filter(|s| !s.is_empty());

        // Remote MQTT configuration
        println!("\n🌐 Remote MQTT Broker Configuration");
        println!("Configure connection to your cloud MQTT provider (AWS IoT, Azure IoT, Google Cloud, or any MQTT broker)");
        config.mqtt_remote_host = self.prompt_with_default(
            "Remote MQTT Host (e.g., your-iot-endpoint.amazonaws.com, your-hub.azure-devices.net)",
            &config.mqtt_remote_host,
            |s| !s.trim().is_empty(),
        )?;

        config.mqtt_remote_port = self
            .prompt_with_default(
                "Remote MQTT Port (1883=standard, 8883=TLS, 443=websockets)",
                &config.mqtt_remote_port.to_string(),
                |s| s.parse::<u16>().is_ok(),
            )?
            .parse()?;

        config.mqtt_remote_tls = self.prompt_yes_no(
            "Use TLS for remote MQTT connection? (recommended for cloud providers)",
            config.mqtt_remote_tls,
        )?;

        let use_auth = self.prompt_yes_no(
            "Use username/password authentication for remote MQTT? (Note: Some providers use certificate-only auth)",
            config.mqtt_remote_username.is_some(),
        )?;

        if use_auth {
            config.mqtt_remote_username = Some(self.prompt_with_default(
                "Remote MQTT Username (device ID for cloud providers)",
                config.mqtt_remote_username.as_deref().unwrap_or(""),
                |s| !s.trim().is_empty(),
            )?);

            config.mqtt_remote_password = Some(self.prompt_password("Remote MQTT Password/Token")?);
        }

        // Local MQTT configuration
        println!("\n🏠 Local MQTT Broker Configuration");
        config.mqtt_local_username =
            self.prompt_with_default("Local MQTT Username", &config.mqtt_local_username, |s| {
                !s.trim().is_empty()
            })?;

        config.mqtt_local_password =
            self.prompt_with_default("Local MQTT Password", &config.mqtt_local_password, |s| {
                s.len() >= 8
            })?;

        // Additional settings
        println!("\n⚙️  Additional Settings");
        config.health_report_interval = self
            .prompt_with_default(
                "Health report interval (seconds)",
                &config.health_report_interval.to_string(),
                |s| s.parse::<u32>().is_ok() && s.parse::<u32>().unwrap() > 0,
            )?
            .parse()?;

        config.ssh_enabled =
            self.prompt_yes_no("Enable SSH tunnel management?", config.ssh_enabled)?;

        if config.ssh_enabled {
            config.ssh_port = self
                .prompt_with_default("SSH port", &config.ssh_port.to_string(), |s| {
                    s.parse::<u16>().is_ok() && s.parse::<u16>().unwrap() > 0
                })?
                .parse()?;
        }

        config.plugins_docker_enabled = self.prompt_yes_no(
            "Enable Docker plugin support?",
            config.plugins_docker_enabled,
        )?;

        println!("\n✅ Configuration complete!");
        Ok(config)
    }

    async fn automatic_setup(&self) -> Result<SetupConfig> {
        info!("Running automatic setup with defaults...");
        Ok(SetupConfig::default())
    }

    fn prompt_with_default<F>(&self, prompt: &str, default: &str, validator: F) -> Result<String>
    where
        F: Fn(&str) -> bool,
    {
        loop {
            print!("{} [{}]: ", prompt, default);
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            let value = if input.is_empty() {
                default.to_string()
            } else {
                input.to_string()
            };

            if validator(&value) {
                return Ok(value);
            } else {
                println!("❌ Invalid input. Please try again.");
            }
        }
    }

    fn prompt_yes_no(&self, prompt: &str, default: bool) -> Result<bool> {
        let default_str = if default { "Y/n" } else { "y/N" };

        loop {
            print!("{} [{}]: ", prompt, default_str);
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            match input.as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => println!("❌ Please enter 'y' or 'n'"),
            }
        }
    }

    fn prompt_password(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);
        io::stdout().flush()?;

        // Note: In a real implementation, you'd want to use a crate like `rpassword`
        // to hide password input. For now, we'll use regular input with a warning.
        println!("⚠️  Password will be visible on screen");

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    async fn generate_certificates(&self, config: &SetupConfig) -> Result<()> {
        info!("Generating certificates...");

        // Generate device certificate
        self.cert_manager
            .create_device_certificate(
                &config.gateway_id,
                vec![
                    "localhost".to_string(),
                    config.gateway_id.clone(),
                    "aetheric-edge".to_string(),
                ],
            )
            .await
            .context("Failed to generate device certificate")?;

        info!("✅ Certificates generated successfully");
        Ok(())
    }

    async fn configure_local_mqtt(&self, config: &SetupConfig) -> Result<()> {
        info!("Configuring local MQTT broker...");

        // Create aetheric-specific mosquitto configuration directory
        let mosquitto_conf_dir = self.config_dir.join("mosquitto-conf");
        fs::create_dir_all(&mosquitto_conf_dir)
            .context("Failed to create mosquitto-conf directory")?;

        // Create aetheric-specific mosquitto configuration file
        let aetheric_mosquitto_conf = mosquitto_conf_dir.join("aetheric.conf");
        let mosquitto_config = format!(
            r#"# Aetheric Edge MQTT Configuration

# Basic settings
persistence true
persistence_location {}/mosquitto/
log_dest file {}/mosquitto.log
log_type error
log_type warning  
log_type notice
log_type information
log_timestamp true
connection_messages true

# Security
allow_anonymous false
password_file {}/mosquitto.passwd

# Additional listener for Aetheric Edge (if not conflicting)
listener 1884 localhost
protocol mqtt

# Message size limits
message_size_limit 100000000

# Connection limits
max_connections 1000
max_inflight_messages 100
max_queued_messages 1000

# Persistence settings
autosave_interval 1800
autosave_on_changes false
persistent_client_expiration 2h
"#,
            self.data_dir.display(),
            PlatformPaths::log_dir().display(),
            self.config_dir.display()
        );

        fs::write(&aetheric_mosquitto_conf, mosquitto_config)
            .context("Failed to create aetheric mosquitto configuration")?;

        // Note: mosquitto include configuration is now handled by MqttBrokerManager

        // Create mosquitto password file
        let passwd_file = self.config_dir.join("mosquitto.passwd");
        let output = Command::new("mosquitto_passwd")
            .args(["-c", "-b"])
            .arg(&passwd_file)
            .arg(&config.mqtt_local_username)
            .arg(&config.mqtt_local_password)
            .output()
            .context("Failed to create mosquitto password file")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create mosquitto password: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Set permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&passwd_file)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&passwd_file, perms)?;
        }

        info!("✅ Local MQTT broker configured");
        Ok(())
    }

    async fn create_aetheric_config(&self, config: &SetupConfig) -> Result<()> {
        info!("Creating Aetheric configuration...");

        let aetheric_config = AethericConfig {
            gateway: crate::config::GatewayConfig {
                id: config.gateway_id.clone(),
                name: config.gateway_name.clone(),
                location: config.gateway_location.clone(),
                description: config.gateway_description.clone(),
            },
            mqtt: crate::config::MqttConfig {
                host: "localhost".to_string(), // Connect to local broker
                port: 1884,                    // Use our custom Aetheric listener port
                username: Some(config.mqtt_local_username.clone()),
                password: Some(config.mqtt_local_password.clone()),
                tls: false, // Local connection doesn't need TLS
                ca_cert_path: None,
                client_cert_path: Some(self.cert_manager.device_cert_path()),
                client_key_path: Some(self.cert_manager.device_key_path()),
            },
            certificates: crate::config::CertificateConfig {
                cert_dir: self
                    .cert_manager
                    .ca_cert_path()
                    .parent()
                    .unwrap()
                    .to_path_buf(),
                auto_renew: true,
                renew_days_threshold: 30,
            },
            health: crate::config::HealthConfig {
                report_interval_seconds: config.health_report_interval as u64,
                metrics_enabled: true,
            },
            ssh: crate::config::SshConfig {
                enabled: config.ssh_enabled,
                port: config.ssh_port,
                max_sessions: 10,
                session_timeout_minutes: 30,
            },
            plugins: crate::config::PluginsConfig {
                install_dir: self.data_dir.join("plugins"),
                temp_dir: self.data_dir.join("temp"),
                docker_enabled: config.plugins_docker_enabled,
                max_concurrent_installs: 3,
            },
        };

        let config_file = self.config_dir.join("aetheric.toml");
        aetheric_config
            .save_to_file(&config_file)
            .context("Failed to save Aetheric configuration")?;

        info!("✅ Aetheric configuration created");
        Ok(())
    }

    async fn configure_mqtt_bridge(&self, config: &SetupConfig) -> Result<()> {
        info!("Configuring MQTT bridge...");

        // Create bridge configuration file in mosquitto-conf directory
        let mosquitto_conf_dir = self.config_dir.join("mosquitto-conf");
        let bridge_conf = mosquitto_conf_dir.join("bridge.conf");

        let bridge_config = format!(
            r#"# Aetheric Edge MQTT Bridge Configuration
# Bridge to remote MQTT broker for cloud connectivity
# Compatible with: AWS IoT Core, Azure IoT Hub, Google Cloud IoT, HiveMQ Cloud, etc.

connection aetheric-remote-bridge
address {}:{}
topic aetheric/+/# both 0 aetheric/{}/
topic aetheric/{}/+/# both 0
{}{}{}
bridge_protocol_version mqttv311
bridge_insecure {}
keepalive_interval 60
restart_timeout 10
try_private true
cleansession true
bridge_attempt_unsubscribe true
"#,
            config.mqtt_remote_host,
            config.mqtt_remote_port,
            config.gateway_id,
            config.gateway_id,
            if let Some(username) = &config.mqtt_remote_username {
                format!("remote_username {}\n", username)
            } else {
                String::new()
            },
            if let Some(password) = &config.mqtt_remote_password {
                format!("remote_password {}\n", password)
            } else {
                String::new()
            },
            if config.mqtt_remote_tls {
                "bridge_cafile /etc/ssl/certs/ca-certificates.crt\n"
            } else {
                ""
            },
            !config.mqtt_remote_tls
        );

        fs::write(&bridge_conf, bridge_config).context("Failed to create bridge configuration")?;

        info!("✅ MQTT bridge configured");
        Ok(())
    }

    async fn configure_sudo_access(&self) -> Result<()> {
        info!("Configuring sudo access for aetheric user...");

        let sudoers_content = r#"# Aetheric Edge Agent - Allow aetheric user to execute specific system commands
# Based on thin-edge.io security model for edge device management
aetheric ALL = (ALL) NOPASSWD:SETENV: /usr/local/bin/aetheric, /usr/local/bin/aetheric-agent, /bin/sync, /sbin/init, /sbin/reboot, /sbin/shutdown
aetheric ALL = (ALL) NOPASSWD:SETENV: /bin/systemctl *, /usr/bin/systemctl *
aetheric ALL = (ALL) NOPASSWD:SETENV: /usr/bin/apt *, /usr/bin/yum *, /usr/bin/dnf *, /usr/bin/apk *
"#;

        let sudoers_file = PathBuf::from("/etc/sudoers.d/aetheric-edge");

        // Write sudoers file
        fs::write(&sudoers_file, sudoers_content)
            .context("Failed to create sudoers configuration")?;

        // Set correct permissions (sudoers files must be 440)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&sudoers_file)?.permissions();
            perms.set_mode(0o440); // Read-only for owner and group, no access for others
            fs::set_permissions(&sudoers_file, perms)?;
        }

        // Validate sudoers syntax
        let output = Command::new("visudo")
            .args(["-c", "-f"])
            .arg(&sudoers_file)
            .output()
            .context("Failed to validate sudoers file")?;

        if !output.status.success() {
            // Remove the invalid file
            let _ = fs::remove_file(&sudoers_file);
            return Err(anyhow::anyhow!(
                "Invalid sudoers configuration: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        info!("✅ Sudo access configured for aetheric user");
        Ok(())
    }

    async fn setup_services(&self) -> Result<()> {
        info!("Setting up cross-platform services...");

        // Check if we have privileges for service installation
        if PlatformPaths::requires_elevated_privileges_for_service() {
            warn!("Service installation requires elevated privileges, skipping service setup...");
            info!("To install services later, run 'aetheric setup --install-services' with elevated privileges");
            return Ok(());
        }

        // Install Mosquitto first
        MqttBrokerManager::install_mosquitto().await?;

        // Configure Mosquitto to include our configuration
        MqttBrokerManager::configure_mosquitto_include(&self.config_dir).await?;

        // Install Aetheric Edge Agent service
        let executable_path = PlatformPaths::executable_path();
        let config_path = self.config_dir.join("aetheric.toml");

        let service_manager = ServiceManager::new(executable_path, config_path);

        // Install and configure the service
        service_manager.install_service().await?;
        service_manager.enable_service().await?;

        // Try to start Mosquitto service (platform-specific)
        self.start_mosquitto_service().await?;

        // Note: We don't auto-start aetheric-agent as it needs configuration first
        info!("✅ Cross-platform services configured");
        Ok(())
    }

    async fn start_mosquitto_service(&self) -> Result<()> {
        info!("Starting Mosquitto service...");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["enable", "mosquitto"])
                .output()
                .context("Failed to enable mosquitto service")?;

            if !output.status.success() {
                warn!(
                    "Failed to enable mosquitto: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let output = Command::new("systemctl")
                .args(["start", "mosquitto"])
                .output()
                .context("Failed to start mosquitto service")?;

            if !output.status.success() {
                warn!(
                    "Failed to start mosquitto: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                info!("✅ Mosquitto service started");
            }
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, Mosquitto is typically run as a service
            let output = Command::new("sc")
                .args(&["start", "mosquitto"])
                .output()
                .context("Failed to start mosquitto service")?;

            if !output.status.success() {
                warn!(
                    "Failed to start mosquitto service: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                info!(
                    "You may need to install and configure Mosquitto as a Windows service manually"
                );
            } else {
                info!("✅ Mosquitto service started");
            }
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS with Homebrew, use brew services
            let output = Command::new("brew")
                .args(&["services", "start", "mosquitto"])
                .output()
                .context("Failed to start mosquitto service")?;

            if !output.status.success() {
                warn!(
                    "Failed to start mosquitto service: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                info!("✅ Mosquitto service started");
            }
        }

        Ok(())
    }

    async fn verify_setup(&self) -> Result<()> {
        info!("Verifying setup...");

        // Check configuration files exist
        let required_files = [
            self.config_dir.join("aetheric.toml"),
            self.config_dir.join("mosquitto-conf").join("aetheric.conf"),
            self.config_dir.join("mosquitto.passwd"),
        ];

        for file in &required_files {
            if !file.exists() {
                return Err(anyhow::anyhow!("Required file missing: {}", file.display()));
            }
        }

        // Check Aetheric service status using cross-platform method
        let executable_path = PlatformPaths::executable_path();
        let config_path = self.config_dir.join("aetheric.toml");
        let service_manager = ServiceManager::new(executable_path, config_path);

        match service_manager.service_status().await {
            Ok(status) => {
                info!("✅ Aetheric service status: {}", status);
            }
            Err(e) => {
                warn!("⚠️  Could not check Aetheric service status: {}", e);
            }
        }

        // Check Mosquitto service status (platform-specific)
        self.check_mosquitto_status().await?;

        info!("✅ Setup verification completed");
        Ok(())
    }

    async fn check_mosquitto_status(&self) -> Result<()> {
        info!("Checking Mosquitto service status...");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["is-active", "mosquitto"])
                .output()
                .context("Failed to check mosquitto status")?;

            let status_output = String::from_utf8_lossy(&output.stdout);
            let status = status_output.trim();
            if status == "active" {
                info!("✅ Mosquitto service is running");
            } else {
                warn!("⚠️  Mosquitto service status: {}", status);
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["query", "mosquitto"])
                .output()
                .context("Failed to check mosquitto status")?;

            if output.status.success() {
                let status_output = String::from_utf8_lossy(&output.stdout);
                if status_output.contains("RUNNING") {
                    info!("✅ Mosquitto service is running");
                } else {
                    warn!("⚠️  Mosquitto service is not running");
                }
            } else {
                warn!("⚠️  Could not check Mosquitto service status");
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("brew")
                .args(&["services", "list"])
                .output()
                .context("Failed to check mosquitto status")?;

            if output.status.success() {
                let status_output = String::from_utf8_lossy(&output.stdout);
                if status_output.contains("mosquitto") && status_output.contains("started") {
                    info!("✅ Mosquitto service is running");
                } else {
                    warn!("⚠️  Mosquitto service is not running");
                }
            } else {
                warn!("⚠️  Could not check Mosquitto service status");
            }
        }

        Ok(())
    }

    fn print_next_steps(&self, options: &SetupOptions) -> Result<()> {
        println!("\n🎉 Setup Complete!");
        println!("==================");
        println!();
        println!("Next steps:");
        println!("1. Verify services are running:");
        #[cfg(target_os = "linux")]
        {
            println!("   sudo systemctl status aetheric-agent");
            println!("   sudo systemctl status mosquitto");
        }
        #[cfg(target_os = "windows")]
        {
            println!("   sc query aetheric-agent");
            println!("   sc query mosquitto");
        }
        #[cfg(target_os = "macos")]
        {
            println!("   launchctl print system/com.aetheric.agent");
            println!("   brew services list | grep mosquitto");
        }
        println!();

        println!("2. Check logs:");
        #[cfg(target_os = "linux")]
        {
            println!("   sudo journalctl -u aetheric-agent -f");
            println!("   sudo journalctl -u mosquitto -f");
        }
        #[cfg(target_os = "windows")]
        {
            println!("   Check Windows Event Viewer for Aetheric Edge Agent logs");
            println!("   Check C:\\ProgramData\\AethericEdge\\Logs\\");
        }
        #[cfg(target_os = "macos")]
        {
            println!("   tail -f /usr/local/var/log/aetheric-edge/stderr.log");
            println!("   brew services info mosquitto");
        }
        println!();

        println!("3. Test MQTT connectivity:");
        println!(
            "   mosquitto_pub -h localhost -p 1884 -u aetheric -P [password] -t aetheric/test -m 'Hello'"
        );
        println!();

        println!("4. Configuration files:");
        println!(
            "   - Main config: {}",
            self.config_dir.join("aetheric.toml").display()
        );
        println!(
            "   - MQTT config: {}",
            self.config_dir.join("mosquitto-conf").display()
        );
        println!("   - Data directory: {}", self.data_dir.display());
        println!();

        if !options.skip_services {
            println!("5. Service management:");
            #[cfg(target_os = "linux")]
            {
                println!("   sudo systemctl start|stop|restart aetheric-agent");
                println!("   sudo systemctl start|stop|restart mosquitto");
            }
            #[cfg(target_os = "windows")]
            {
                println!("   sc start|stop aetheric-agent");
                println!("   sc start|stop mosquitto");
                println!("   Or use Services.msc GUI");
            }
            #[cfg(target_os = "macos")]
            {
                println!(
                    "   sudo launchctl load|unload /Library/LaunchDaemons/com.aetheric.agent.plist"
                );
                println!("   brew services start|stop|restart mosquitto");
            }
            println!();
        }

        Ok(())
    }
}

fn generate_password() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut hasher);

    format!("aetheric-{}", hasher.finish())
}
