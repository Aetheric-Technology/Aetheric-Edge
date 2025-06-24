use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

/// Simplified cross-platform service management for Aetheric Edge
pub struct ServiceManager {
    service_name: String,
    description: String,
    executable_path: PathBuf,
    config_path: PathBuf,
}

impl ServiceManager {
    pub fn new(executable_path: PathBuf, config_path: PathBuf) -> Self {
        Self {
            service_name: "aetheric-agent".to_string(),
            description: "MQTT-based edge computing agent for IoT device management".to_string(),
            executable_path,
            config_path,
        }
    }

    /// Install the service on the current platform
    pub async fn install_service(&self) -> Result<()> {
        info!("Installing Aetheric Edge Agent service...");

        #[cfg(target_os = "linux")]
        {
            self.install_systemd_service().await
        }
        #[cfg(target_os = "windows")]
        {
            self.install_windows_service().await
        }
        #[cfg(target_os = "macos")]
        {
            self.install_launchd_service().await
        }
    }

    /// Start the service
    pub async fn start_service(&self) -> Result<()> {
        info!("Starting Aetheric Edge Agent service...");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["start", &self.service_name])
                .output()
                .context("Failed to start service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["start", &self.service_name])
                .output()
                .context("Failed to start service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let plist_path = format!(
                "/Library/LaunchDaemons/com.aetheric.{}.plist",
                self.service_name
            );
            let output = Command::new("launchctl")
                .args(&["load", &plist_path])
                .output()
                .context("Failed to start service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        info!("✅ Service started successfully");
        Ok(())
    }

    /// Stop the service
    pub async fn stop_service(&self) -> Result<()> {
        info!("Stopping Aetheric Edge Agent service...");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["stop", &self.service_name])
                .output()
                .context("Failed to stop service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["stop", &self.service_name])
                .output()
                .context("Failed to stop service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let plist_path = format!(
                "/Library/LaunchDaemons/com.aetheric.{}.plist",
                self.service_name
            );
            let output = Command::new("launchctl")
                .args(&["unload", &plist_path])
                .output()
                .context("Failed to stop service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        info!("✅ Service stopped successfully");
        Ok(())
    }

    /// Enable the service to start automatically
    pub async fn enable_service(&self) -> Result<()> {
        info!("Enabling Aetheric Edge Agent service for auto-start...");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["enable", &self.service_name])
                .output()
                .context("Failed to enable service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to enable service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Windows services are typically auto-start by default when installed
            info!("Windows service auto-start configured during installation");
        }
        #[cfg(target_os = "macos")]
        {
            // launchd services are enabled when the plist is installed
            info!("macOS service auto-start configured via launchd plist");
        }

        info!("✅ Service enabled for auto-start");
        Ok(())
    }

    /// Check service status
    pub async fn service_status(&self) -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["is-active", &self.service_name])
                .output()
                .context("Failed to check service status")?;

            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["query", &self.service_name])
                .output()
                .context("Failed to check service status")?;

            let status_output = String::from_utf8_lossy(&output.stdout);
            if status_output.contains("RUNNING") {
                Ok("running".to_string())
            } else if status_output.contains("STOPPED") {
                Ok("stopped".to_string())
            } else {
                Ok("unknown".to_string())
            }
        }
        #[cfg(target_os = "macos")]
        {
            let plist_path = format!(
                "/Library/LaunchDaemons/com.aetheric.{}.plist",
                self.service_name
            );
            let output = Command::new("launchctl")
                .args(&["list"])
                .output()
                .context("Failed to check service status")?;

            let status_output = String::from_utf8_lossy(&output.stdout);
            if status_output.contains(&format!("com.aetheric.{}", self.service_name)) {
                Ok("running".to_string())
            } else {
                Ok("stopped".to_string())
            }
        }
    }

    /// Uninstall the service
    pub async fn uninstall_service(&self) -> Result<()> {
        info!("Uninstalling Aetheric Edge Agent service...");

        #[cfg(target_os = "linux")]
        {
            // Stop and disable first
            let _ = self.stop_service().await;

            let output = Command::new("systemctl")
                .args(["disable", &self.service_name])
                .output()
                .context("Failed to disable service")?;

            if !output.status.success() {
                warn!(
                    "Failed to disable service: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            // Remove service file
            let service_file = format!("/etc/systemd/system/{}.service", self.service_name);
            if std::path::Path::new(&service_file).exists() {
                std::fs::remove_file(&service_file)
                    .context("Failed to remove systemd service file")?;
            }

            // Reload systemd
            let _ = Command::new("systemctl").args(["daemon-reload"]).output();
        }
        #[cfg(target_os = "windows")]
        {
            let _ = self.stop_service().await;

            let output = Command::new("sc")
                .args(&["delete", &self.service_name])
                .output()
                .context("Failed to uninstall service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to uninstall service: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let _ = self.stop_service().await;

            let plist_path = format!(
                "/Library/LaunchDaemons/com.aetheric.{}.plist",
                self.service_name
            );
            if std::path::Path::new(&plist_path).exists() {
                std::fs::remove_file(&plist_path).context("Failed to remove launchd plist file")?;
            }
        }

        info!("✅ Service uninstalled successfully");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn install_systemd_service(&self) -> Result<()> {
        info!("Creating systemd service...");

        let service_file_path = format!("/etc/systemd/system/{}.service", self.service_name);
        // Determine the actual user who will run the service
        let actual_user = std::env::var("SUDO_USER").unwrap_or_else(|_| "admin".to_string());
        let user_config_path = if actual_user == "root" {
            self.config_path.display().to_string()
        } else {
            format!("/home/{}/.aetheric/aetheric.toml", actual_user)
        };

        let service_content = format!(
            r#"[Unit]
Description={description}
Documentation=https://github.com/Aetheric-Technology/Aetheric-Edge
After=network.target
Wants=network.target
Requires=mosquitto.service

[Service]
Type=simple
User={user}
RuntimeDirectory=aetheric-agent
ExecStartPre=+-{executable} init
ExecStart={executable} --config {config}
Restart=always
RestartSec=10
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
"#,
            description = self.description,
            user = actual_user,
            executable = self.executable_path.display(),
            config = user_config_path
        );

        std::fs::write(&service_file_path, service_content)
            .context("Failed to write systemd service file")?;

        // Reload systemd daemon
        let output = Command::new("systemctl")
            .args(["daemon-reload"])
            .output()
            .context("Failed to reload systemd daemon")?;

        if !output.status.success() {
            warn!(
                "Failed to reload systemd daemon: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        info!("✅ Systemd service installed");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn install_windows_service(&self) -> Result<()> {
        info!("Creating Windows service...");

        let output = Command::new("sc")
            .args(&[
                "create",
                &self.service_name,
                "binPath=",
                &format!(
                    "\"{}\" --config \"{}\"",
                    self.executable_path.display(),
                    self.config_path.display()
                ),
                "DisplayName=",
                "Aetheric Edge Agent",
                "start=",
                "auto",
            ])
            .output()
            .context("Failed to create Windows service")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create Windows service: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Set service description
        let _ = Command::new("sc")
            .args(&["description", &self.service_name, &self.description])
            .output();

        info!("✅ Windows service installed");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn install_launchd_service(&self) -> Result<()> {
        info!("Creating launchd service...");

        let plist_path = format!(
            "/Library/LaunchDaemons/com.aetheric.{}.plist",
            self.service_name
        );
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aetheric.{service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>--config</string>
        <string>{config}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/aetheric-edge/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/aetheric-edge/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>/usr/local/var/lib/aetheric-edge</string>
</dict>
</plist>"#,
            service_name = self.service_name,
            executable = self.executable_path.display(),
            config = self.config_path.display()
        );

        std::fs::write(&plist_path, plist_content).context("Failed to write launchd plist file")?;

        // Set proper permissions
        let output = Command::new("chmod")
            .args(&["644", &plist_path])
            .output()
            .context("Failed to set plist permissions")?;

        if !output.status.success() {
            warn!(
                "Failed to set plist permissions: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        info!("✅ launchd service installed");
        Ok(())
    }
}

/// Get platform-specific configuration paths
pub struct PlatformPaths;

impl PlatformPaths {
    pub fn config_dir() -> PathBuf {
        Self::home_aetheric_dir()
    }

    pub fn data_dir() -> PathBuf {
        Self::home_aetheric_dir().join("data")
    }

    pub fn log_dir() -> PathBuf {
        Self::home_aetheric_dir().join("logs")
    }

    pub fn home_aetheric_dir() -> PathBuf {
        if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".aetheric")
        } else {
            // Fallback if home directory cannot be determined
            #[cfg(target_os = "windows")]
            {
                PathBuf::from("C:\\Users\\Default\\.aetheric")
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                PathBuf::from("/tmp/.aetheric")
            }
        }
    }

    pub fn system_config_dir() -> PathBuf {
        // System-wide config for services that need elevated privileges
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/etc/aetheric-edge")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from("C:\\ProgramData\\AethericEdge")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/usr/local/etc/aetheric-edge")
        }
    }

    pub fn executable_path() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/usr/local/bin/aetheric-agent")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from("C:\\Program Files\\AethericEdge\\aetheric-agent.exe")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/usr/local/bin/aetheric-agent")
        }
    }

    pub fn requires_elevated_privileges() -> bool {
        // For home directory setup, we don't need elevated privileges
        // Only service installation requires elevated privileges
        false
    }

    pub fn requires_elevated_privileges_for_service() -> bool {
        // Service installation always requires elevated privileges
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Check if we're root (UID 0)
            let current_user = std::env::var("USER").unwrap_or_default();
            current_user != "root"
        }
        #[cfg(target_os = "windows")]
        {
            // On Windows, check if we're running as administrator
            use std::ptr;
            use winapi::um::handleapi::CloseHandle;
            use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
            use winapi::um::securitybaseapi::GetTokenInformation;
            use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

            unsafe {
                let mut token_handle = ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
                    return true; // Assume we need elevation if we can't check
                }

                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

                let result = GetTokenInformation(
                    token_handle,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    size,
                    &mut size,
                );

                CloseHandle(token_handle);

                if result == 0 {
                    return true; // Assume we need elevation if we can't check
                }

                elevation.TokenIsElevated == 0
            }
        }
    }
}

/// Cross-platform MQTT broker management
pub struct MqttBrokerManager;

impl MqttBrokerManager {
    pub async fn install_mosquitto() -> Result<()> {
        info!("Installing Mosquitto MQTT broker...");

        #[cfg(target_os = "linux")]
        {
            Self::install_mosquitto_linux().await
        }
        #[cfg(target_os = "windows")]
        {
            Self::install_mosquitto_windows().await
        }
        #[cfg(target_os = "macos")]
        {
            Self::install_mosquitto_macos().await
        }
    }

    #[cfg(target_os = "linux")]
    async fn install_mosquitto_linux() -> Result<()> {
        info!("Installing Mosquitto on Linux...");

        // Detect package manager and install
        if std::process::Command::new("which")
            .arg("apt")
            .output()?
            .status
            .success()
        {
            std::process::Command::new("apt")
                .args(["update"])
                .status()
                .context("Failed to update package list")?;

            std::process::Command::new("apt")
                .args(["install", "-y", "mosquitto", "mosquitto-clients"])
                .status()
                .context("Failed to install Mosquitto via apt")?;
        } else if std::process::Command::new("which")
            .arg("yum")
            .output()?
            .status
            .success()
        {
            std::process::Command::new("yum")
                .args(["install", "-y", "mosquitto"])
                .status()
                .context("Failed to install Mosquitto via yum")?;
        } else if std::process::Command::new("which")
            .arg("dnf")
            .output()?
            .status
            .success()
        {
            std::process::Command::new("dnf")
                .args(["install", "-y", "mosquitto"])
                .status()
                .context("Failed to install Mosquitto via dnf")?;
        } else {
            return Err(anyhow::anyhow!(
                "No supported package manager found (apt, yum, dnf)"
            ));
        }

        info!("✅ Mosquitto installed successfully on Linux");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn install_mosquitto_windows() -> Result<()> {
        info!("Installing Mosquitto on Windows...");
        warn!(
            "Mosquitto installation on Windows requires manual setup or chocolatey package manager"
        );
        warn!("Please install Mosquitto manually from: https://mosquitto.org/download/");
        warn!("Or use chocolatey: choco install mosquitto");

        // Check if Mosquitto is already installed
        if std::process::Command::new("where")
            .arg("mosquitto")
            .output()?
            .status
            .success()
        {
            info!("✅ Mosquitto is already installed");
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Mosquitto is not installed. Please install it manually."
        ))
    }

    #[cfg(target_os = "macos")]
    async fn install_mosquitto_macos() -> Result<()> {
        info!("Installing Mosquitto on macOS...");

        // Try to install via Homebrew
        if std::process::Command::new("which")
            .arg("brew")
            .output()?
            .status
            .success()
        {
            std::process::Command::new("brew")
                .args(&["install", "mosquitto"])
                .status()
                .context("Failed to install Mosquitto via Homebrew")?;

            info!("✅ Mosquitto installed successfully via Homebrew");
        } else {
            warn!(
                "Homebrew not found. Please install Mosquitto manually or install Homebrew first"
            );
            return Err(anyhow::anyhow!(
                "Homebrew is required to install Mosquitto on macOS"
            ));
        }

        Ok(())
    }

    pub async fn configure_mosquitto_include(config_dir: &std::path::Path) -> Result<()> {
        info!("Configuring Mosquitto include directory...");

        #[cfg(target_os = "linux")]
        let mosquitto_conf_path = PathBuf::from("/etc/mosquitto/mosquitto.conf");
        #[cfg(target_os = "windows")]
        let mosquitto_conf_path = PathBuf::from("C:\\Program Files\\mosquitto\\mosquitto.conf");
        #[cfg(target_os = "macos")]
        let mosquitto_conf_path = PathBuf::from("/usr/local/etc/mosquitto/mosquitto.conf");

        if !mosquitto_conf_path.exists() {
            warn!(
                "Mosquitto configuration file not found at: {}",
                mosquitto_conf_path.display()
            );
            return Ok(());
        }

        let include_dir = config_dir.join("mosquitto-conf");
        let include_line = format!("include_dir {}", include_dir.display());

        // Read existing config
        let existing_content = std::fs::read_to_string(&mosquitto_conf_path)
            .context("Failed to read mosquitto.conf")?;

        // Check if our include is already present
        if existing_content.contains(&include_line) {
            info!("Aetheric include already present in mosquitto.conf");
            return Ok(());
        }

        // Check if there are already any include_dir lines that might conflict
        if existing_content.lines().filter(|line| line.trim().starts_with("include_dir")).count() > 0 {
            info!("Include directory already configured in mosquitto.conf");
            return Ok(());
        }

        // Add include directive
        let updated_content = format!("{}\n{}", existing_content, include_line);

        // Write updated config
        std::fs::write(&mosquitto_conf_path, updated_content)
            .context("Failed to update mosquitto.conf")?;

        info!("✅ Added Aetheric include to mosquitto.conf");
        Ok(())
    }
}
