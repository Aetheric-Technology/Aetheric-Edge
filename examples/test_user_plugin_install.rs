use aetheric_edge::agent::command_handler::CommandHandler;
use aetheric_edge::agent::ssh_tunnel::SshTunnelManager;
use aetheric_edge::config::{
    AethericConfig, CertificateConfig, GatewayConfig, HealthConfig, MqttConfig, PluginsConfig,
    SshConfig,
};
use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use base64::{engine::general_purpose, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏠 Installing plugin to ~/.aetheric/plugins (no sudo required!)");

    // Get user's home directory
    let home = dirs::home_dir().expect("Could not find home directory");
    let aetheric_home = home.join(".aetheric");

    // Create directories
    std::fs::create_dir_all(&aetheric_home.join("plugins"))?;
    std::fs::create_dir_all(&aetheric_home.join("tmp"))?;
    std::fs::create_dir_all(&aetheric_home.join("certs"))?;

    println!("📁 Created directories in: {}", aetheric_home.display());

    // Create config using user home directory
    let config = Arc::new(AethericConfig {
        gateway: GatewayConfig {
            id: "user-test-gateway".to_string(),
            name: Some("User Test Gateway".to_string()),
            location: Some("Home".to_string()),
            description: Some("Testing plugin installation in user directory".to_string()),
        },
        mqtt: MqttConfig {
            host: "localhost".to_string(),
            port: 1883,
            username: None,
            password: None,
            tls: false,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        },
        certificates: CertificateConfig {
            cert_dir: aetheric_home.join("certs"),
            auto_renew: false,
            renew_days_threshold: 30,
        },
        health: HealthConfig {
            report_interval_seconds: 30,
            metrics_enabled: true,
        },
        ssh: SshConfig {
            enabled: true,
            port: 22,
            max_sessions: 5,
            session_timeout_minutes: 30,
        },
        plugins: PluginsConfig {
            install_dir: aetheric_home.join("plugins"),
            temp_dir: aetheric_home.join("tmp"),
            docker_enabled: true,
            max_concurrent_installs: 5,
        },
    });

    // Create mock MQTT client
    let (command_sender, _command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "user-test-gateway".to_string(),
        command_sender,
    )
    .await?;
    let mqtt_client_arc = Arc::new(mqtt_client);

    // Create SSH tunnel manager and command handler
    let ssh_tunnel_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    let command_handler = CommandHandler::new(config.clone(), ssh_tunnel_manager);

    // Create a useful monitoring plugin
    let monitoring_script = r#"#!/bin/bash
# User Home Monitoring Plugin
echo "🏠 User Home Monitoring Plugin v1.0"
echo "Installed in: $(dirname $0)"
echo "Running as user: $(whoami)"
echo "No sudo needed! ✅"
echo ""

while true; do
    echo "=== Home System Status $(date) ==="
    
    # Home directory usage
    echo "📁 Home directory usage:"
    du -sh ~ 2>/dev/null || echo "  Could not check home directory size"
    
    # Available disk space
    echo "💾 Available disk space:"
    df -h ~ | tail -1 | awk '{print "  " $4 " available (" $5 " used)"}'
    
    # Memory usage (if available)
    if command -v free &> /dev/null; then
        echo "🧠 Memory usage:"
        free -h | grep Mem | awk '{print "  " $3 " / " $2 " used"}'
    fi
    
    # Load average (if available)
    if command -v uptime &> /dev/null; then
        echo "⚡ System load:"
        uptime | awk -F'load average:' '{print "  " $2}'
    fi
    
    # Network connectivity test
    echo "🌐 Network test:"
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo "  Internet connectivity: ✅"
    else
        echo "  Internet connectivity: ❌"
    fi
    
    echo "  Next check in 30 seconds..."
    echo ""
    sleep 30
done
"#;

    // Base64 encode the script
    let base64_data = general_purpose::STANDARD.encode(monitoring_script.as_bytes());

    // Create install command
    let install_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "home-monitor".to_string(),
            source: PluginSource::Base64 {
                data: base64_data,
                checksum: None,
                checksum_type: None,
            },
            config: Some(PluginConfig {
                name: "home-monitor".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Home system monitoring plugin".to_string()),
                plugin_type: PluginType::Script,
                auto_start: false,
                environment: HashMap::from([
                    ("HOME_MONITOR_INTERVAL".to_string(), "30".to_string()),
                    ("LOG_LEVEL".to_string(), "info".to_string()),
                ]),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    println!("📦 Installing 'home-monitor' plugin...");

    // Install the plugin
    let response = command_handler.handle_command(install_command).await;

    println!("📋 Installation result:");
    println!("   Status: {:?}", response.status);
    println!("   Message: {}", response.message);

    if response.status == CommandStatus::Success {
        let plugin_path = config.plugins.install_dir.join("home-monitor");
        let binary_path = plugin_path.join("plugin.sh");

        println!("✅ Plugin installed successfully!");
        println!("   Location: {}", plugin_path.display());
        println!("   Executable: {}", binary_path.display());

        // Check if files exist
        if plugin_path.exists() {
            println!("   Directory exists: ✅");
        }
        if binary_path.exists() {
            println!("   Script exists: ✅");

            // Check permissions
            let metadata = std::fs::metadata(&binary_path)?;
            let permissions = metadata.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = permissions.mode();
                println!(
                    "   Permissions: {:o} (executable: {})",
                    mode,
                    mode & 0o111 != 0
                );
            }
        }

        println!("");
        println!("🎉 Success! Plugin installed in user home directory");
        println!("   No sudo required!");
        println!("   You can run it with: {}", binary_path.display());

        // Show directory structure
        println!("");
        println!("📁 Plugin directory structure:");
        if let Ok(entries) = std::fs::read_dir(&plugin_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    println!("   └── {}", entry.file_name().to_string_lossy());
                }
            }
        }
    } else {
        println!("❌ Installation failed: {}", response.message);
    }

    Ok(())
}
