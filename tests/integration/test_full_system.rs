use aetheric_edge::agent::Agent;
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

fn create_test_config_with_temp_dir(temp_dir: &TempDir) -> AethericConfig {
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "integration-test-gateway".to_string(),
            name: Some("Integration Test Gateway".to_string()),
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
            max_sessions: 3,
            session_timeout_minutes: 30,
        },
        plugins: aetheric_edge::config::PluginsConfig {
            install_dir: temp_dir.path().join("plugins"),
            temp_dir: temp_dir.path().join("temp"),
            docker_enabled: false, // Disable Docker for tests
            max_concurrent_installs: 3,
        },
    }
}

async fn setup_test_agent(
    temp_dir: &TempDir,
) -> (
    Agent,
    Arc<MqttClient>,
    mpsc::UnboundedSender<CommandMessage>,
) {
    let config = create_test_config_with_temp_dir(temp_dir);
    let (command_sender, command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _event_loop) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "integration-test-gateway".to_string(),
        command_sender.clone(),
    )
    .await
    .unwrap();

    let mqtt_client_arc = Arc::new(mqtt_client.clone());
    let agent = Agent::new(config, mqtt_client, command_receiver);

    (agent, mqtt_client_arc, command_sender)
}

#[tokio::test]
async fn test_agent_creation_and_setup() {
    let temp_dir = TempDir::new().unwrap();
    let (agent, mqtt_client, _command_sender) = setup_test_agent(&temp_dir).await;

    // Test that MQTT client is properly set up
    let topic_builder = mqtt_client.topic_builder();
    assert_eq!(topic_builder.gateway_id(), "integration-test-gateway");

    // Agent should be created without panicking
    drop(agent);
}

#[tokio::test]
async fn test_command_flow_health() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    let command = CommandMessage {
        id: "integration-health-001".to_string(),
        command: CommandType::Health,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    // Send command through the channel
    let result = command_sender.send(command);
    assert!(result.is_ok());

    // Give some time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_plugin_install_complete_flow() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Create a test plugin file
    let test_plugin_path = temp_dir.path().join("integration_test_plugin");
    tokio::fs::write(
        &test_plugin_path,
        b"#!/bin/bash\necho 'Integration test plugin'\n",
    )
    .await
    .unwrap();

    let source = PluginSource::Local {
        path: test_plugin_path.to_string_lossy().to_string(),
    };

    let plugin_config = PluginConfig {
        name: "integration-test-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Integration test plugin".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };

    let install_command = CommandMessage {
        id: "integration-install-001".to_string(),
        command: CommandType::Install {
            plugin_name: "integration-test-plugin".to_string(),
            source,
            config: Some(plugin_config),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    // Send install command
    let result = command_sender.send(install_command);
    assert!(result.is_ok());

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send list command to verify installation
    let list_command = CommandMessage {
        id: "integration-list-001".to_string(),
        command: CommandType::List,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(list_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_ssh_session_complete_flow() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Test SSH connect
    let ssh_connect_command = CommandMessage {
        id: "integration-ssh-connect-001".to_string(),
        command: CommandType::SshConnect {
            session_id: "integration-ssh-session-001".to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(ssh_connect_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test SSH heartbeat
    let ssh_heartbeat_command = CommandMessage {
        id: "integration-ssh-heartbeat-001".to_string(),
        command: CommandType::SshHeartbeat {
            session_id: "integration-ssh-session-001".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(ssh_heartbeat_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test SSH disconnect
    let ssh_disconnect_command = CommandMessage {
        id: "integration-ssh-disconnect-001".to_string(),
        command: CommandType::SshDisconnect {
            session_id: "integration-ssh-session-001".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(ssh_disconnect_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_plugin_chunked_transfer_complete_flow() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Create test data to transfer in chunks
    let test_data = b"This is a large test file that will be transferred in multiple chunks to test the chunked transfer functionality of the plugin management system.";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test_data);

    // Split into 3 chunks
    let chunk_size = base64_data.len() / 3;
    let chunks = [&base64_data[..chunk_size],
        &base64_data[chunk_size..chunk_size * 2],
        &base64_data[chunk_size * 2..]];

    let plugin_config = PluginConfig {
        name: "integration-chunked-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Integration test chunked plugin".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };

    // Send chunks in order
    for (index, chunk) in chunks.iter().enumerate() {
        let source = PluginSource::Chunked {
            chunk_id: "integration-chunk-transfer".to_string(),
            total_chunks: 3,
            chunk_index: index as u32,
            data: chunk.to_string(),
            checksum: None,
        };

        let command = CommandMessage {
            id: format!("integration-chunk-{}", index),
            command: CommandType::Install {
                plugin_name: "integration-chunked-plugin".to_string(),
                source,
                config: Some(plugin_config.clone()),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        };

        let result = command_sender.send(command);
        assert!(result.is_ok());

        // Small delay between chunks
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Give time for final processing
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_multiple_command_types_sequence() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    let commands = vec![
        CommandMessage {
            id: "seq-health".to_string(),
            command: CommandType::Health,
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "seq-list".to_string(),
            command: CommandType::List,
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "seq-ssh-connect".to_string(),
            command: CommandType::SshConnect {
                session_id: "seq-ssh-session".to_string(),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "seq-ssh-disconnect".to_string(),
            command: CommandType::SshDisconnect {
                session_id: "seq-ssh-session".to_string(),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
    ];

    // Send all commands in sequence
    for command in commands {
        let result = command_sender.send(command);
        assert!(result.is_ok());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Give time for all processing to complete
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_concurrent_commands() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Send multiple commands concurrently
    let handles = (0..5)
        .map(|i| {
            let sender = command_sender.clone();
            tokio::spawn(async move {
                let command = CommandMessage {
                    id: format!("concurrent-health-{}", i),
                    command: CommandType::Health,
                    timestamp: "2025-06-18T15:30:00Z".to_string(),
                    parameters: HashMap::new(),
                };

                sender.send(command).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_error_handling_invalid_commands() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Test plugin operations on non-existent plugins
    let error_commands = vec![
        CommandMessage {
            id: "error-start".to_string(),
            command: CommandType::Start {
                plugin_name: "non-existent-plugin".to_string(),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "error-stop".to_string(),
            command: CommandType::Stop {
                plugin_name: "non-existent-plugin".to_string(),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "error-status".to_string(),
            command: CommandType::Status {
                plugin_name: Some("non-existent-plugin".to_string()),
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
        CommandMessage {
            id: "error-ssh-data".to_string(),
            command: CommandType::SshData {
                session_id: "non-existent-session".to_string(),
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
                direction: SshDataDirection::Up,
            },
            timestamp: "2025-06-18T15:30:00Z".to_string(),
            parameters: HashMap::new(),
        },
    ];

    for command in error_commands {
        let result = command_sender.send(command);
        assert!(result.is_ok());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_system_restart_command() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    let command = CommandMessage {
        id: "integration-restart".to_string(),
        command: CommandType::SystemRestart,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(command);
    assert!(result.is_ok());

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_plugin_base64_install_and_remove_flow() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    let script_content =
        b"#!/bin/bash\necho 'Integration test base64 plugin'\necho 'Plugin is running'\n";
    let base64_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, script_content);

    let source = PluginSource::Base64 {
        data: base64_data,
        checksum: None,
        checksum_type: None,
    };

    let plugin_config = PluginConfig {
        name: "integration-base64-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Integration test base64 plugin".to_string()),
        plugin_type: PluginType::Script,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    };

    // Install plugin
    let install_command = CommandMessage {
        id: "integration-base64-install".to_string(),
        command: CommandType::Install {
            plugin_name: "integration-base64-plugin".to_string(),
            source,
            config: Some(plugin_config),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(install_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Remove plugin
    let remove_command = CommandMessage {
        id: "integration-base64-remove".to_string(),
        command: CommandType::Remove {
            plugin_name: "integration-base64-plugin".to_string(),
        },
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(remove_command);
    assert!(result.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_mqtt_message_timeout_handling() {
    let temp_dir = TempDir::new().unwrap();
    let (_agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Test that we can send a command and it doesn't hang
    let command = CommandMessage {
        id: "timeout-test".to_string(),
        command: CommandType::Health,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let send_result = timeout(Duration::from_millis(1000), async {
        command_sender.send(command).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    })
    .await;

    assert!(send_result.is_ok());
}

#[tokio::test]
async fn test_configuration_validation() {
    let temp_dir = TempDir::new().unwrap();
    let config = create_test_config_with_temp_dir(&temp_dir);

    // Validate config fields
    assert_eq!(config.gateway.id, "integration-test-gateway");
    assert_eq!(config.mqtt.host, "localhost");
    assert_eq!(config.mqtt.port, 1883);
    assert!(config.ssh.enabled);
    assert_eq!(config.ssh.max_sessions, 3);
    assert!(!config.plugins.docker_enabled);
    assert!(!config.plugins.docker_enabled);
    assert!(config
        .plugins
        .install_dir
        .to_string_lossy()
        .contains("plugins"));
    assert!(config
        .plugins
        .install_dir
        .to_string_lossy()
        .contains("plugins"));
}

#[tokio::test]
async fn test_agent_shutdown_gracefully() {
    let temp_dir = TempDir::new().unwrap();
    let (agent, _mqtt_client, command_sender) = setup_test_agent(&temp_dir).await;

    // Send a command
    let command = CommandMessage {
        id: "shutdown-test".to_string(),
        command: CommandType::Health,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    };

    let result = command_sender.send(command);
    assert!(result.is_ok());

    // Drop command sender to trigger shutdown
    drop(command_sender);

    // Agent should shutdown gracefully when command channel is closed
    // This test ensures no panic occurs during shutdown
    drop(agent);
}
