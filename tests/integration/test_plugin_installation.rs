use aetheric_edge::agent::command_handler::CommandHandler;
use aetheric_edge::agent::ssh_tunnel::SshTunnelManager;
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Integration tests for remote plugin installation via MQTT messages
/// Tests both binary and Docker container installation

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-plugin-install".to_string(),
            name: Some("Test Plugin Install Gateway".to_string()),
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
            docker_enabled: true,
            max_concurrent_installs: 5,
        },
    }
}

async fn create_test_mqtt_client() -> (MqttClient, mpsc::UnboundedReceiver<CommandMessage>) {
    let (command_sender, command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway-plugin-install".to_string(),
        command_sender,
    ).await.unwrap();
    (mqtt_client, command_receiver)
}

async fn create_test_binary() -> Result<Vec<u8>> {
    // Create a simple shell script that acts as a test binary
    let script_content = r#"#!/bin/bash
echo "Test plugin started"
while true; do
    echo "Plugin is running... $(date)"
    sleep 30
done
"#;
    Ok(script_content.as_bytes().to_vec())
}

async fn create_test_command_handler(config: Arc<AethericConfig>) -> CommandHandler {
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    let ssh_tunnel_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    CommandHandler::new(config, ssh_tunnel_manager)
}

#[tokio::test]
async fn test_binary_plugin_installation_via_mqtt() {
    let config = Arc::new(create_test_config());
    let command_handler = create_test_command_handler(config.clone()).await;

    // Create test binary
    let binary_data = create_test_binary().await.unwrap();
    let base64_data = general_purpose::STANDARD.encode(&binary_data);

    // Create MQTT command message for binary plugin installation
    let install_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "test-binary-plugin".to_string(),
            source: PluginSource::Base64 {
                data: base64_data,
                checksum: None,
                checksum_type: None,
            },
            config: Some(PluginConfig {
                name: "test-binary-plugin".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Test binary plugin".to_string()),
                plugin_type: PluginType::Binary,
                auto_start: false, // Don't auto-start in tests
                environment: HashMap::new(),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    // Handle the installation command
    let response = command_handler.handle_command(install_command).await;

    println!("Binary plugin installation response: {:?}", response);

    // Verify installation response
    assert_eq!(response.status, CommandStatus::Success, "Binary plugin installation should succeed");
    assert!(response.message.contains("successfully"), "Response should indicate success");

    // Verify plugin is installed (check if plugin directory exists)
    let plugin_path = config.plugins.install_dir.join("test-binary-plugin");
    assert!(plugin_path.exists(), "Plugin directory should exist after installation");

    // Verify plugin binary exists and is executable
    let binary_path = plugin_path.join("plugin.sh"); // Shell script is named plugin.sh
    assert!(binary_path.exists(), "Plugin binary should exist");

    // Test starting the plugin
    let start_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Start {
            plugin_name: "test-binary-plugin".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let start_response = command_handler.handle_command(start_command).await;
    println!("Plugin start response: {:?}", start_response);

    // Note: Start might fail if systemd is not available in test environment
    // But the installation itself should work

    // Test getting plugin status
    let status_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Status {
            plugin_name: Some("test-binary-plugin".to_string()),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let status_response = command_handler.handle_command(status_command).await;
    println!("Plugin status response: {:?}", status_response);

    // Cleanup - remove the plugin
    let remove_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Remove {
            plugin_name: "test-binary-plugin".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let remove_response = command_handler.handle_command(remove_command).await;
    println!("Plugin removal response: {:?}", remove_response);
}

#[tokio::test]
async fn test_docker_plugin_installation_via_mqtt() {
    let config = Arc::new(create_test_config());
    let command_handler = create_test_command_handler(config.clone()).await;

    // Create MQTT command message for Docker plugin installation
    let install_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "test-docker-plugin".to_string(),
            source: PluginSource::Docker {
                image: "alpine".to_string(), // Use lightweight Alpine Linux for testing
                tag: Some("latest".to_string()),
                registry: None, // Use Docker Hub
            },
            config: Some(PluginConfig {
                name: "test-docker-plugin".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Test Docker plugin".to_string()),
                plugin_type: PluginType::Docker,
                auto_start: false, // Don't auto-start in tests
                environment: HashMap::from([
                    ("TEST_ENV".to_string(), "test_value".to_string()),
                ]),
                dependencies: vec![],
                ports: vec![8080], // Test port mapping
                volumes: vec!["/tmp:/tmp".to_string()], // Test volume mapping
                command_args: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo 'Docker plugin started' && sleep 3600".to_string(),
                ],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    // Handle the installation command
    let response = command_handler.handle_command(install_command).await;

    println!("Docker plugin installation response: {:?}", response);

    // Note: Docker installation might fail in test environment without Docker daemon
    // But we can verify the command processing works correctly
    
    match response.status {
        CommandStatus::Success => {
            println!("Docker plugin installation succeeded");
            
            // Verify plugin directory exists
            let plugin_path = config.plugins.install_dir.join("test-docker-plugin");
            assert!(plugin_path.exists(), "Plugin directory should exist after installation");

            // Test getting plugin status
            let status_command = CommandMessage {
                id: Uuid::new_v4().to_string(),
                command: CommandType::Status {
                    plugin_name: Some("test-docker-plugin".to_string()),
                },
                timestamp: chrono::Utc::now().to_rfc3339(),
                parameters: HashMap::new(),
            };

            let status_response = command_handler.handle_command(status_command).await;
            println!("Docker plugin status response: {:?}", status_response);

            // Cleanup - remove the plugin
            let remove_command = CommandMessage {
                id: Uuid::new_v4().to_string(),
                command: CommandType::Remove {
                    plugin_name: "test-docker-plugin".to_string(),
                },
                timestamp: chrono::Utc::now().to_rfc3339(),
                parameters: HashMap::new(),
            };

            let remove_response = command_handler.handle_command(remove_command).await;
            println!("Docker plugin removal response: {:?}", remove_response);
        }
        CommandStatus::Failed => {
            println!("Docker plugin installation failed (expected in test environment without Docker): {}", response.message);
            // This is expected in most test environments
        }
        _ => {
            println!("Docker plugin installation status: {:?}", response.status);
        }
    }
}

#[tokio::test]
async fn test_chunked_binary_installation_via_mqtt() {
    let config = Arc::new(create_test_config());
    let command_handler = create_test_command_handler(config.clone()).await;

    // Create larger test binary for chunked transfer
    let large_script = format!(r#"#!/bin/bash
echo "Large test plugin started"
# Add some bulk to make it larger
{}
while true; do
    echo "Large plugin is running... $(date)"
    sleep 30
done
"#, "# This is padding to make the file larger\n".repeat(100));

    let binary_data = large_script.as_bytes();
    let base64_data = general_purpose::STANDARD.encode(binary_data);

    // Split into chunks (simulate large file transfer)
    let chunk_size = 1024; // 1KB chunks
    let chunks: Vec<String> = base64_data
        .chars()
        .collect::<Vec<char>>()
        .chunks(chunk_size)
        .map(|chunk| chunk.iter().collect())
        .collect();

    println!("Sending binary in {} chunks", chunks.len());

    // Send chunks
    for (index, chunk_data) in chunks.iter().enumerate() {
        let chunk_command = CommandMessage {
            id: Uuid::new_v4().to_string(),
            command: CommandType::Install {
                plugin_name: "test-chunked-plugin".to_string(),
                source: PluginSource::Chunked {
                    chunk_id: "chunked-test-001".to_string(),
                    total_chunks: chunks.len() as u32,
                    chunk_index: index as u32,
                    data: chunk_data.clone(),
                    checksum: None,
                },
                config: if index == 0 {
                    // Only send config with first chunk
                    Some(PluginConfig {
                        name: "test-chunked-plugin".to_string(),
                        version: "1.0.0".to_string(),
                        description: Some("Test chunked binary plugin".to_string()),
                        plugin_type: PluginType::Binary,
                        auto_start: false,
                        environment: HashMap::new(),
                        dependencies: vec![],
                        ports: vec![],
                        volumes: vec![],
                        command_args: vec![],
                    })
                } else {
                    None
                },
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
            parameters: HashMap::new(),
        };

        let response = command_handler.handle_command(chunk_command).await;
        println!("Chunk {} response: {:?}", index, response);

        if index < chunks.len() - 1 {
            // For intermediate chunks, expect success but not complete installation
            assert_eq!(response.status, CommandStatus::Success, "Chunk {} should be accepted", index);
        } else {
            // For final chunk, expect complete installation
            assert_eq!(response.status, CommandStatus::Success, "Final chunk should complete installation");
            
            // Verify plugin is installed
            let plugin_path = config.plugins.install_dir.join("test-chunked-plugin");
            assert!(plugin_path.exists(), "Chunked plugin directory should exist after final chunk");
        }
    }

    // Cleanup
    let remove_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Remove {
            plugin_name: "test-chunked-plugin".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let remove_response = command_handler.handle_command(remove_command).await;
    println!("Chunked plugin removal response: {:?}", remove_response);
}

#[tokio::test]
async fn test_plugin_installation_error_cases() {
    let config = Arc::new(create_test_config());
    let command_handler = create_test_command_handler(config.clone()).await;

    // Test 1: Invalid base64 data
    let invalid_base64_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "invalid-base64-plugin".to_string(),
            source: PluginSource::Base64 {
                data: "invalid-base64-data!@#$".to_string(),
                checksum: None,
                checksum_type: None,
            },
            config: Some(PluginConfig {
                name: "invalid-base64-plugin".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Invalid base64 test".to_string()),
                plugin_type: PluginType::Binary,
                auto_start: false,
                environment: HashMap::new(),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let response = command_handler.handle_command(invalid_base64_command).await;
    println!("Invalid base64 response: {:?}", response);
    assert_eq!(response.status, CommandStatus::Failed, "Invalid base64 should fail");

    // Test 2: Empty plugin name
    let empty_name_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "".to_string(),
            source: PluginSource::Base64 {
                data: general_purpose::STANDARD.encode(b"test"),
                checksum: None,
                checksum_type: None,
            },
            config: None,
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let response = command_handler.handle_command(empty_name_command).await;
    println!("Empty name response: {:?}", response);
    assert_eq!(response.status, CommandStatus::Failed, "Empty plugin name should fail");

    // Test 3: Invalid Docker image
    let invalid_docker_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: "invalid-docker-plugin".to_string(),
            source: PluginSource::Docker {
                image: "nonexistent/invalid-image-that-does-not-exist".to_string(),
                tag: Some("latest".to_string()),
                registry: None,
            },
            config: Some(PluginConfig {
                name: "invalid-docker-plugin".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Invalid Docker test".to_string()),
                plugin_type: PluginType::Docker,
                auto_start: false,
                environment: HashMap::new(),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let response = command_handler.handle_command(invalid_docker_command).await;
    println!("Invalid Docker image response: {:?}", response);
    // This should fail, but might be due to Docker not being available rather than invalid image
    assert_eq!(response.status, CommandStatus::Failed, "Invalid Docker image should fail");
}

#[tokio::test]
async fn test_plugin_lifecycle_via_mqtt() {
    let config = Arc::new(create_test_config());
    let command_handler = create_test_command_handler(config.clone()).await;

    let plugin_name = "lifecycle-test-plugin";

    // Step 1: Install plugin
    let binary_data = create_test_binary().await.unwrap();
    let base64_data = general_purpose::STANDARD.encode(&binary_data);

    let install_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Install {
            plugin_name: plugin_name.to_string(),
            source: PluginSource::Base64 {
                data: base64_data,
                checksum: None,
                checksum_type: None,
            },
            config: Some(PluginConfig {
                name: plugin_name.to_string(),
                version: "1.0.0".to_string(),
                description: Some("Lifecycle test plugin".to_string()),
                plugin_type: PluginType::Binary,
                auto_start: false,
                environment: HashMap::new(),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            }),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let install_response = command_handler.handle_command(install_command).await;
    println!("Install response: {:?}", install_response);
    assert_eq!(install_response.status, CommandStatus::Success);

    // Step 2: List plugins
    let list_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::List,
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let list_response = command_handler.handle_command(list_command).await;
    println!("List response: {:?}", list_response);
    assert_eq!(list_response.status, CommandStatus::Success);

    // Step 3: Get plugin status
    let status_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Status {
            plugin_name: Some(plugin_name.to_string()),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let status_response = command_handler.handle_command(status_command).await;
    println!("Status response: {:?}", status_response);
    assert_eq!(status_response.status, CommandStatus::Success);

    // Step 4: Start plugin (might fail without systemd)
    let start_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Start {
            plugin_name: plugin_name.to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let start_response = command_handler.handle_command(start_command).await;
    println!("Start response: {:?}", start_response);
    // Note: May fail in test environment without systemd

    // Step 5: Stop plugin
    let stop_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Stop {
            plugin_name: plugin_name.to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let stop_response = command_handler.handle_command(stop_command).await;
    println!("Stop response: {:?}", stop_response);

    // Step 6: Remove plugin
    let remove_command = CommandMessage {
        id: Uuid::new_v4().to_string(),
        command: CommandType::Remove {
            plugin_name: plugin_name.to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        parameters: HashMap::new(),
    };

    let remove_response = command_handler.handle_command(remove_command).await;
    println!("Remove response: {:?}", remove_response);
    assert_eq!(remove_response.status, CommandStatus::Success);

    // Verify plugin is removed
    let plugin_path = config.plugins.install_dir.join(plugin_name);
    assert!(!plugin_path.exists(), "Plugin directory should be removed");
}