use aetheric_edge::agent::plugin_manager::{PluginManager, PluginSource, PluginConfig, PluginType};
use aetheric_edge::config::{AethericConfig, PluginsConfig};
use std::sync::Arc;
use std::collections::HashMap;
use base64::{engine::general_purpose, Engine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration with ~/.aetheric/plugins directory
    let home = dirs::home_dir().expect("Could not find home directory");
    let aetheric_home = home.join(".aetheric");
    
    // Create directories if they don't exist
    std::fs::create_dir_all(&aetheric_home.join("plugins"))?;
    std::fs::create_dir_all(&aetheric_home.join("tmp"))?;
    
    let mut config = AethericConfig::default();
    config.plugins = PluginsConfig {
        install_dir: aetheric_home.join("plugins"),
        temp_dir: aetheric_home.join("tmp"),
        docker_enabled: true,
        max_concurrent_installs: 5,
    };
    
    let config = Arc::new(config);
    let plugin_manager = PluginManager::new(config.clone());
    
    // Example 1: Install a simple monitoring script
    println!("📦 Installing system monitor plugin...");
    
    let monitor_script = r#"#!/bin/bash
# Simple system monitoring plugin
echo "System Monitor v1.0 starting..."

while true; do
    echo "=== System Status $(date) ==="
    echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory: $(free -h | grep Mem | awk '{print $3 " / " $2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $3 " / " $2 " (" $5 ")"}')"
    echo ""
    sleep 60
done
"#;
    
    // Base64 encode the script
    let encoded_script = general_purpose::STANDARD.encode(monitor_script.as_bytes());
    
    // Create plugin configuration
    let plugin_config = PluginConfig {
        name: "system-monitor".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Simple system monitoring plugin".to_string()),
        plugin_type: PluginType::Script,
        auto_start: false,
        environment: HashMap::from([
            ("LOG_LEVEL".to_string(), "info".to_string()),
        ]),
        dependencies: vec![],
        ports: vec![],
        volumes: vec![],
        command_args: vec![],
    };
    
    // Install the plugin
    let result = plugin_manager.install_plugin(
        "system-monitor",
        &PluginSource::Base64 {
            data: encoded_script,
            checksum: None,
            checksum_type: None,
        },
        plugin_config,
    ).await?;
    
    println!("✅ Plugin installed: {}", serde_json::to_string_pretty(&result)?);
    
    // Example 2: Install a binary plugin from URL
    println!("\n📦 Installing binary plugin from URL...");
    
    let binary_config = PluginConfig {
        name: "data-collector".to_string(),
        version: "2.0.0".to_string(),
        description: Some("Data collection service".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: true,
        environment: HashMap::from([
            ("MQTT_HOST".to_string(), "localhost".to_string()),
            ("MQTT_PORT".to_string(), "1883".to_string()),
        ]),
        dependencies: vec![],
        ports: vec![8080],
        volumes: vec![],
        command_args: vec!["--config".to_string(), "/etc/collector.conf".to_string()],
    };
    
    // This would install from a real URL in production
    /*
    let result = plugin_manager.install_plugin(
        "data-collector",
        &PluginSource::Url {
            url: "https://example.com/downloads/data-collector-v2.0.0".to_string(),
            checksum: Some("d8e8fca2dc0f896fd7cb4cb0031ba249".to_string()),
            checksum_type: Some("md5".to_string()),
        },
        binary_config,
    ).await?;
    */
    
    // Example 3: Install Docker container plugin
    println!("\n📦 Installing Docker container plugin...");
    
    let docker_config = PluginConfig {
        name: "redis-cache".to_string(),
        version: "7.0".to_string(),
        description: Some("Redis caching service".to_string()),
        plugin_type: PluginType::Docker,
        auto_start: true,
        environment: HashMap::from([
            ("REDIS_PASSWORD".to_string(), "secure-password".to_string()),
        ]),
        dependencies: vec![],
        ports: vec![6379],
        volumes: vec!["redis-data:/data".to_string()],
        command_args: vec!["redis-server".to_string(), "--appendonly".to_string(), "yes".to_string()],
    };
    
    // This would pull and install a Docker container
    /*
    let result = plugin_manager.install_plugin(
        "redis-cache",
        &PluginSource::Docker {
            image: "redis".to_string(),
            tag: Some("7-alpine".to_string()),
            registry: None,
        },
        docker_config,
    ).await?;
    */
    
    // List installed plugins
    println!("\n📋 Installed plugins:");
    let plugins = plugin_manager.list_plugins().await?;
    println!("{}", serde_json::to_string_pretty(&plugins)?);
    
    // Check where plugins are installed
    let plugin_dir = config.plugins.install_dir.display();
    println!("\n✅ Plugins installed in: {}", plugin_dir);
    println!("   No sudo required! You own this directory.");
    
    Ok(())
}