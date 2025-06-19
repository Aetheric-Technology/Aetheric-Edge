use aetheric_edge::agent::command_handler::CommandHandler;
use aetheric_edge::agent::ssh_tunnel::SshTunnelManager;
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;

fn create_test_config_with_temp_dir(temp_dir: &TempDir) -> AethericConfig {
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway".to_string(),
            name: Some("Test Gateway".to_string()),
            location: None,
            description: None,
        },
        mqtt: aetheric_edge::config::MqttConfig {
            host: "localhost".to_string(),
            port: 1883,
            username: None,
            password: None,
            tls: false,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        },
        certificates: aetheric_edge::config::CertificateConfig {
            cert_dir: temp_dir.path().join("certs"),
            auto_renew: false,
            renew_days_threshold: 30,
        },
        health: aetheric_edge::config::HealthConfig {
            report_interval_seconds: 30,
            metrics_enabled: true,
        },
        ssh: aetheric_edge::config::SshConfig {
            enabled: true,
            port: 22,
            max_sessions: 5,
            session_timeout_minutes: 30,
        },
        plugins: aetheric_edge::config::PluginsConfig {
            install_dir: temp_dir.path().join("plugins"),
            temp_dir: temp_dir.path().join("temp"),
            docker_enabled: false, // Disable Docker for unit tests
            max_concurrent_installs: 5,
        },
    }
}

async fn create_test_setup(temp_dir: &TempDir) -> (CommandHandler, Arc<AethericConfig>) {
    let config = Arc::new(create_test_config_with_temp_dir(temp_dir));
    let (command_sender, _command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway".to_string(),
        command_sender,
    ).await.unwrap();
    let mqtt_client_arc = Arc::new(mqtt_client);
    let ssh_tunnel_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    let command_handler = CommandHandler::new(config.clone(), ssh_tunnel_manager);
    
    (command_handler, config)
}

#[tokio::test]
async fn test_health_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "health-cmd-001".to_string(),
        command: CommandType::Health,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "health-cmd-001");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert!(result["gateway_id"].as_str().unwrap() == "test-gateway");
    assert!(result.get("uptime").is_some());
    assert!(result.get("memory_usage").is_some());
    assert!(result.get("cpu_usage").is_some());
    assert!(result.get("disk_usage").is_some());
    assert!(result.get("network_status").is_some());
}

#[tokio::test]
async fn test_plugin_install_local_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, config) = create_test_setup(&temp_dir).await;
    
    // Create a test binary file
    let test_binary_path = temp_dir.path().join("test_plugin");
    tokio::fs::write(&test_binary_path, b"#!/bin/bash\necho 'Hello from plugin'\n").await.unwrap();
    
    let source = PluginSource::Local {
        path: test_binary_path.to_string_lossy().to_string(),
    };
    
    let plugin_config = PluginConfig {
        name: "test-local-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Test local plugin".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };
    
    let command = CommandMessage {
        id: "install-cmd-001".to_string(),
        command: CommandType::Install {
            plugin_name: "test-local-plugin".to_string(),
            source,
            config: Some(plugin_config),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "install-cmd-001");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["plugin_name"], "test-local-plugin");
    assert_eq!(result["status"], "installed");
    
    // Verify plugin was actually installed
    let plugin_dir = config.plugins.install_dir.join("test-local-plugin");
    assert!(plugin_dir.exists());
    // Check for the script file since the content starts with #!/bin/bash
    let plugin_file = plugin_dir.join("plugin.sh");
    assert!(plugin_file.exists());
}

#[tokio::test]
async fn test_plugin_install_base64_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, config) = create_test_setup(&temp_dir).await;
    
    let script_content = b"#!/bin/bash\necho 'Hello from base64 plugin'\n";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, script_content);
    
    let source = PluginSource::Base64 {
        data: base64_data,
        checksum: None,
        checksum_type: None,
    };
    
    let plugin_config = PluginConfig {
        name: "test-base64-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Test base64 plugin".to_string()),
        plugin_type: PluginType::Script,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };
    
    let command = CommandMessage {
        id: "install-cmd-002".to_string(),
        command: CommandType::Install {
            plugin_name: "test-base64-plugin".to_string(),
            source,
            config: Some(plugin_config),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "install-cmd-002");
    assert!(matches!(response.status, CommandStatus::Success));
    
    // Verify plugin was installed
    let plugin_dir = config.plugins.install_dir.join("test-base64-plugin");
    assert!(plugin_dir.exists());
    let plugin_file = plugin_dir.join("plugin.sh");
    assert!(plugin_file.exists());
    let content = tokio::fs::read(&plugin_file).await.unwrap();
    assert_eq!(content, script_content);
}

#[tokio::test]
async fn test_plugin_remove_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, config) = create_test_setup(&temp_dir).await;
    
    // First install a plugin
    let test_binary_path = temp_dir.path().join("test_plugin_remove");
    tokio::fs::write(&test_binary_path, b"#!/bin/bash\necho 'Test'\n").await.unwrap();
    
    let install_source = PluginSource::Local {
        path: test_binary_path.to_string_lossy().to_string(),
    };
    
    let plugin_config = PluginConfig {
        name: "test-remove-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Test plugin for removal".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };
    
    let install_command = CommandMessage {
        id: "install-cmd-003".to_string(),
        command: CommandType::Install {
            plugin_name: "test-remove-plugin".to_string(),
            source: install_source,
            config: Some(plugin_config),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let install_response = command_handler.handle_command(install_command).await;
    assert!(matches!(install_response.status, CommandStatus::Success));
    
    // Now remove the plugin
    let remove_command = CommandMessage {
        id: "remove-cmd-001".to_string(),
        command: CommandType::Remove {
            plugin_name: "test-remove-plugin".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(remove_command).await;
    
    assert_eq!(response.command_id, "remove-cmd-001");
    assert!(matches!(response.status, CommandStatus::Success));
    
    let result = response.result.unwrap();
    assert_eq!(result["plugin_name"], "test-remove-plugin");
    assert_eq!(result["status"], "removed");
    
    // Verify plugin directory was removed
    let plugin_dir = config.plugins.install_dir.join("test-remove-plugin");
    assert!(!plugin_dir.exists());
}

#[tokio::test]
async fn test_plugin_list_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "list-cmd-001".to_string(),
        command: CommandType::List,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "list-cmd-001");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert!(result.get("plugins").is_some());
    let plugins = result["plugins"].as_array().unwrap();
    // Initially should be empty
    assert_eq!(plugins.len(), 0);
}

#[tokio::test]
async fn test_plugin_start_stop_restart_commands() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    // Test start command for non-existent plugin
    let start_command = CommandMessage {
        id: "start-cmd-001".to_string(),
        command: CommandType::Start {
            plugin_name: "non-existent-plugin".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(start_command).await;
    assert!(matches!(response.status, CommandStatus::Failed));
    
    // Test stop command for non-existent plugin
    let stop_command = CommandMessage {
        id: "stop-cmd-001".to_string(),
        command: CommandType::Stop {
            plugin_name: "non-existent-plugin".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(stop_command).await;
    assert!(matches!(response.status, CommandStatus::Failed));
    
    // Test restart command for non-existent plugin
    let restart_command = CommandMessage {
        id: "restart-cmd-001".to_string(),
        command: CommandType::Restart {
            plugin_name: "non-existent-plugin".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(restart_command).await;
    assert!(matches!(response.status, CommandStatus::Failed));
}

#[tokio::test]
async fn test_plugin_status_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    // Test status for specific plugin (non-existent)
    let status_command = CommandMessage {
        id: "status-cmd-001".to_string(),
        command: CommandType::Status {
            plugin_name: Some("non-existent-plugin".to_string()),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(status_command).await;
    assert!(matches!(response.status, CommandStatus::Failed));
    
    // Test status for all plugins
    let status_all_command = CommandMessage {
        id: "status-cmd-002".to_string(),
        command: CommandType::Status {
            plugin_name: None,
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(status_all_command).await;
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_ssh_connect_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "ssh-cmd-001".to_string(),
        command: CommandType::SshConnect {
            session_id: "test-session-001".to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ssh-cmd-001");
    // Response could be success or failed depending on if SSH server is running
    assert!(matches!(response.status, CommandStatus::Success | CommandStatus::Failed));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["session_id"], "test-session-001");
}

#[tokio::test]
async fn test_ssh_disconnect_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "ssh-cmd-002".to_string(),
        command: CommandType::SshDisconnect {
            session_id: "test-session-002".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ssh-cmd-002");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["session_id"], "test-session-002");
    // Should fail since session doesn't exist
    assert_eq!(result["status"], "failed");
}

#[tokio::test]
async fn test_ssh_data_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let test_data = b"echo 'test ssh data'";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test_data);
    
    let command = CommandMessage {
        id: "ssh-cmd-003".to_string(),
        command: CommandType::SshData {
            session_id: "test-session-003".to_string(),
            data: base64_data,
            direction: SshDataDirection::Up,
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ssh-cmd-003");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["session_id"], "test-session-003");
    // Should fail since session doesn't exist
    assert_eq!(result["status"], "failed");
}

#[tokio::test]
async fn test_ssh_heartbeat_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "ssh-cmd-004".to_string(),
        command: CommandType::SshHeartbeat {
            session_id: "test-session-004".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ssh-cmd-004");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["session_id"], "test-session-004");
    // Should fail since session doesn't exist
    assert_eq!(result["status"], "failed");
}

#[tokio::test]
async fn test_system_restart_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "restart-cmd-001".to_string(),
        command: CommandType::SystemRestart,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "restart-cmd-001");
    assert!(matches!(response.status, CommandStatus::Success));
    assert!(response.result.is_some());
    
    let result = response.result.unwrap();
    assert_eq!(result["status"], "restart_scheduled");
    assert_eq!(result["delay_seconds"], 5);
}

#[tokio::test]
async fn test_ota_update_command() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, _config) = create_test_setup(&temp_dir).await;
    
    let command = CommandMessage {
        id: "ota-cmd-001".to_string(),
        command: CommandType::OtaUpdate {
            version: "2.0.0".to_string(),
            url: "https://example.com/nonexistent.bin".to_string(),
            checksum: Some("abc123".to_string()),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ota-cmd-001");
    // Should fail because URL doesn't exist
    assert!(matches!(response.status, CommandStatus::Failed));
    assert!(response.message.contains("Command failed"));
}

#[tokio::test]
async fn test_ssh_disabled_config() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config_with_temp_dir(&temp_dir);
    config.ssh.enabled = false;
    let config = Arc::new(config);
    
    let (command_sender, _command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway".to_string(),
        command_sender,
    ).await.unwrap();
    let mqtt_client_arc = Arc::new(mqtt_client);
    let ssh_tunnel_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    let command_handler = CommandHandler::new(config.clone(), ssh_tunnel_manager);
    
    let command = CommandMessage {
        id: "ssh-cmd-disabled".to_string(),
        command: CommandType::SshConnect {
            session_id: "test-session-disabled".to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "ssh-cmd-disabled");
    assert!(matches!(response.status, CommandStatus::Failed));
    assert!(response.message.contains("SSH functionality is disabled"));
}

#[tokio::test]
async fn test_plugin_install_without_config() {
    let temp_dir = TempDir::new().unwrap();
    let (command_handler, config) = create_test_setup(&temp_dir).await;
    
    // Create a test script file (starts with shebang)
    let test_script_path = temp_dir.path().join("test_script");
    tokio::fs::write(&test_script_path, b"#!/bin/bash\necho 'Hello from script'\n").await.unwrap();
    
    let source = PluginSource::Local {
        path: test_script_path.to_string_lossy().to_string(),
    };
    
    let command = CommandMessage {
        id: "install-cmd-no-config".to_string(),
        command: CommandType::Install {
            plugin_name: "test-no-config-plugin".to_string(),
            source,
            config: None, // No config provided
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };
    
    let response = command_handler.handle_command(command).await;
    
    assert_eq!(response.command_id, "install-cmd-no-config");
    assert!(matches!(response.status, CommandStatus::Success));
    
    // Verify plugin was installed with default config
    let plugin_dir = config.plugins.install_dir.join("test-no-config-plugin");
    assert!(plugin_dir.exists());
}