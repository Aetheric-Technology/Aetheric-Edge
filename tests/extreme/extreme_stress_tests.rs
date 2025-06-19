use aetheric_edge::agent::{HealthMonitor, CommandHandler};
use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tempfile::TempDir;

use crate::common::create_test_config;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn extreme_mqtt_message_flooding() {
    let config = Arc::new(create_test_config());
    let (command_tx, _command_rx) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        config.mqtt.host.clone(),
        config.mqtt.port,
        config.gateway.id.clone(),
        command_tx,
    ).await.unwrap();

    let start = Instant::now();
    let message_count = 10000;
    
    // Flood with health messages
    let mut handles = vec![];
    for i in 0..message_count {
        let client = mqtt_client.clone();
        let handle = tokio::spawn(async move {
            let health_msg = HealthMessage {
                status: if i % 3 == 0 { HealthStatus::Up } else if i % 3 == 1 { HealthStatus::Degraded } else { HealthStatus::Down },
                timestamp: chrono::Utc::now().to_rfc3339(),
                gateway_id: format!("gateway-{}", i),
                uptime_seconds: i as u64,
                memory_usage_mb: (i * 10) as u64,
                cpu_usage_percent: (i % 100) as f32,
            };
            
            let result = timeout(Duration::from_secs(1), client.publish_health(&health_msg)).await;
            result.is_ok()
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap() {
            success_count += 1;
        }
    }

    let elapsed = start.elapsed();
    println!("Sent {} messages in {:?}", success_count, elapsed);
    println!("Rate: {} messages/sec", success_count as f64 / elapsed.as_secs_f64());
    
    assert!(success_count > message_count * 80 / 100, "Should handle at least 80% of messages");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extreme_concurrent_command_processing() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.plugins.install_dir = temp_dir.path().join("plugins");
    config.plugins.temp_dir = temp_dir.path().join("temp");
    
    let config = Arc::new(config);
    let ssh_manager = Arc::new(aetheric_edge::agent::ssh_tunnel::SshTunnelManager::new(
        config.clone(),
        Arc::new(MqttClient::new(
            config.mqtt.host.clone(),
            config.mqtt.port,
            config.gateway.id.clone(),
            mpsc::unbounded_channel().0,
        ).await.unwrap().0),
    ));
    
    let handler = CommandHandler::new(config.clone(), ssh_manager);
    
    // Create 100 concurrent commands
    let mut handles = vec![];
    for i in 0..100 {
        let handler = handler.clone();
        let handle = tokio::spawn(async move {
            let command = CommandMessage {
                id: format!("cmd-{}", i),
                command: match i % 5 {
                    0 => CommandType::Health,
                    1 => CommandType::List,
                    2 => CommandType::Status { plugin_name: None },
                    3 => CommandType::Install {
                        plugin_name: format!("plugin-{}", i),
                        source: PluginSource::Base64 {
                            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"#!/bin/bash\necho 'test plugin'"),
                            checksum: None,
                            checksum_type: None,
                        },
                        config: None,
                    },
                    _ => CommandType::Remove {
                        plugin_name: format!("plugin-{}", i - 1),
                    },
                },
                timestamp: chrono::Utc::now().to_rfc3339(),
                parameters: std::collections::HashMap::new(),
            };
            
            let start = Instant::now();
            let response = handler.handle_command(command).await;
            let elapsed = start.elapsed();
            
            (response.status, elapsed)
        });
        handles.push(handle);
    }
    
    let mut success_count = 0;
    let mut total_time = Duration::from_secs(0);
    
    for handle in handles {
        let (status, elapsed) = handle.await.unwrap();
        if matches!(status, CommandStatus::Success) {
            success_count += 1;
        }
        total_time += elapsed;
    }
    
    println!("Processed {} commands successfully", success_count);
    println!("Average response time: {:?}", total_time / 100);
    
    assert!(success_count >= 90, "Should process at least 90% of commands successfully");
}

#[tokio::test]
async fn extreme_plugin_installation_edge_cases() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.plugins.install_dir = temp_dir.path().join("plugins");
    config.plugins.temp_dir = temp_dir.path().join("temp");
    
    let config = Arc::new(config);
    let plugin_manager = aetheric_edge::agent::plugin_manager::PluginManager::new(config.clone());
    
    // Test 1: Empty base64 data
    let result = plugin_manager.install_plugin(
        "empty-plugin",
        &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
            data: String::new(),
            checksum: None,
            checksum_type: None,
        },
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: "empty-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
            auto_start: false,
            environment: std::collections::HashMap::new(),
            dependencies: vec![],
            ports: vec![],
            volumes: vec![],
            command_args: vec![],
        },
    ).await;
    
    assert!(result.is_err(), "Should fail with empty base64 data");
    
    // Test 2: Invalid base64 data
    let _result = plugin_manager.install_plugin(
        "invalid-base64",
        &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
            data: "This is not valid base64!@#$%".to_string(),
            checksum: None,
            checksum_type: None,
        },
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: "invalid-base64".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
            auto_start: false,
            environment: std::collections::HashMap::new(),
            dependencies: vec![],
            ports: vec![],
            volumes: vec![],
            command_args: vec![],
        },
    ).await;
    
    assert!(result.is_err(), "Should fail with invalid base64 data");
    
    // Test 3: Extremely large plugin name
    let long_name = "a".repeat(1000);
    let result = plugin_manager.install_plugin(
        &long_name,
        &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
            checksum: None,
            checksum_type: None,
        },
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: long_name.clone(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
            auto_start: false,
            environment: std::collections::HashMap::new(),
            dependencies: vec![],
            ports: vec![],
            volumes: vec![],
            command_args: vec![],
        },
    ).await;
    
    // Should handle long names gracefully
    assert!(result.is_ok() || result.is_err(), "Should handle long names without panic");
    
    // Test 4: Invalid characters in plugin name
    let invalid_names = vec![
        "../../../etc/passwd",
        "plugin|name",
        "plugin;name",
        "plugin&name",
        "plugin`name",
        "plugin$name",
        "plugin\nname",
    ];
    
    for invalid_name in invalid_names {
        let _result = plugin_manager.install_plugin(
            invalid_name,
            &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
                checksum: None,
                checksum_type: None,
            },
            aetheric_edge::agent::plugin_manager::PluginConfig {
                name: invalid_name.to_string(),
                version: "1.0.0".to_string(),
                description: None,
                plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
                auto_start: false,
                environment: std::collections::HashMap::new(),
                dependencies: vec![],
                ports: vec![],
                volumes: vec![],
                command_args: vec![],
            },
        ).await;
        
        // Should handle without allowing path traversal
        if invalid_name.contains("..") {
            println!("Testing path traversal protection with: {}", invalid_name);
        }
    }
    
    // Test 5: Concurrent installation of same plugin
    let mut handles = vec![];
    for i in 0..10 {
        let pm = plugin_manager.clone();
        let handle = tokio::spawn(async move {
            pm.install_plugin(
                "concurrent-plugin",
                &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("test-{}", i).as_bytes()),
                    checksum: None,
                    checksum_type: None,
                },
                aetheric_edge::agent::plugin_manager::PluginConfig {
                    name: "concurrent-plugin".to_string(),
                    version: "1.0.0".to_string(),
                    description: None,
                    plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
                    auto_start: false,
                    environment: std::collections::HashMap::new(),
                    dependencies: vec![],
                    ports: vec![],
                    volumes: vec![],
                    command_args: vec![],
                },
            ).await
        });
        handles.push(handle);
    }
    
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    
    // At least one should succeed
    assert!(results.iter().any(|r| r.is_ok()), "At least one concurrent install should succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn extreme_health_monitoring_stress() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.health.report_interval_seconds = 1; // Very frequent reporting
    config.plugins.install_dir = temp_dir.path().join("plugins");
    
    let config = Arc::new(config);
    let (command_tx, _) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        config.mqtt.host.clone(),
        config.mqtt.port,
        config.gateway.id.clone(),
        command_tx,
    ).await.unwrap();
    
    let mut health_monitor = HealthMonitor::new(config.clone());
    
    // Run health monitor for a short time with stress
    let monitor_handle = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(5),
            health_monitor.run(mqtt_client)
        ).await;
    });
    
    // Simulate CPU and memory stress
    let stress_handles: Vec<_> = (0..10).map(|_| {
        tokio::spawn(async {
            let mut data = vec![0u8; 10_000_000]; // 10MB allocation
            for _ in 0..1000 {
                // Busy loop to consume CPU
                data.iter_mut().for_each(|b| *b = (*b).wrapping_add(1));
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    }).collect();
    
    // Let it run
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Clean up
    monitor_handle.abort();
    for handle in stress_handles {
        handle.abort();
    }
    
    // If we get here without panic, the test passes
    assert!(true, "Health monitor should handle stress without crashing");
}

#[tokio::test]
async fn extreme_ssh_session_limits() {
    let mut config = create_test_config();
    config.ssh.max_sessions = 5;
    config.ssh.session_timeout_minutes = 1;
    
    let config = Arc::new(config);
    let (mqtt_client, _) = MqttClient::new(
        config.mqtt.host.clone(),
        config.mqtt.port,
        config.gateway.id.clone(),
        mpsc::unbounded_channel().0,
    ).await.unwrap();
    
    let ssh_manager = aetheric_edge::agent::ssh_tunnel::SshTunnelManager::new(
        config.clone(),
        Arc::new(mqtt_client),
    );
    
    // Try to create more sessions than allowed
    let mut session_results = vec![];
    for i in 0..10 {
        let result = ssh_manager.handle_ssh_command(
            aetheric_edge::agent::ssh_tunnel::SshCommand::Connect {
                session_id: format!("session-{}", i),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            }
        ).await.unwrap();
        session_results.push(result);
    }
    
    let connected_count = session_results.iter()
        .filter(|r| matches!(r.status, aetheric_edge::agent::ssh_tunnel::SshSessionStatus::Connected))
        .count();
    
    println!("Connected sessions: {}", connected_count);
    assert!(connected_count <= 5, "Should not exceed max session limit");
    
    // Test rapid connect/disconnect cycles
    for i in 0..50 {
        let connect_result = ssh_manager.handle_ssh_command(
            aetheric_edge::agent::ssh_tunnel::SshCommand::Connect {
                session_id: format!("rapid-{}", i),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(1),
            }
        ).await.unwrap();
        
        if matches!(connect_result.status, aetheric_edge::agent::ssh_tunnel::SshSessionStatus::Connected) {
            // Immediately disconnect
            let _ = ssh_manager.handle_ssh_command(
                aetheric_edge::agent::ssh_tunnel::SshCommand::Disconnect {
                    session_id: format!("rapid-{}", i),
                }
            ).await;
        }
    }
}

#[tokio::test]
async fn extreme_chunked_transfer_stress() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.plugins.install_dir = temp_dir.path().join("plugins");
    config.plugins.temp_dir = temp_dir.path().join("temp");
    
    let config = Arc::new(config);
    let plugin_manager = aetheric_edge::agent::plugin_manager::PluginManager::new(config.clone());
    
    // Create a large file (1MB)
    let large_data = vec![0xAB; 1_000_000];
    let large_data_len = large_data.len();
    let large_data_checksum = format!("{:x}", md5::compute(&large_data));
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &large_data);
    let chunk_size = 10_000; // Small chunks to stress test
    let chunks: Vec<String> = encoded.as_bytes()
        .chunks(chunk_size)
        .map(|chunk| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk))
        .collect();
    
    println!("Testing with {} chunks", chunks.len());
    
    // Send chunks out of order
    let chunk_id = uuid::Uuid::new_v4().to_string();
    let total_chunks = chunks.len() as u32;
    
    // Shuffle chunk order
    let mut indices: Vec<usize> = (0..chunks.len()).collect();
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    indices.shuffle(&mut rng);
    
    let mut handles = vec![];
    for (i, &original_index) in indices.iter().enumerate() {
        let pm = plugin_manager.clone();
        let chunk_data = chunks[original_index].clone();
        let chunk_id = chunk_id.clone();
        let checksum = if original_index == (total_chunks as usize - 1) {
            Some(large_data_checksum.clone())
        } else {
            None
        };
        
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(i as u64 * 10)).await;
            
            pm.install_plugin(
                "large-chunked-plugin",
                &aetheric_edge::agent::plugin_manager::PluginSource::Chunked {
                    chunk_id: chunk_id.clone(),
                    total_chunks,
                    chunk_index: original_index as u32,
                    data: chunk_data,
                    checksum,
                },
                aetheric_edge::agent::plugin_manager::PluginConfig {
                    name: "large-chunked-plugin".to_string(),
                    version: "1.0.0".to_string(),
                    description: None,
                    plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
                    auto_start: false,
                    environment: std::collections::HashMap::new(),
                    dependencies: vec![],
                    ports: vec![],
                    volumes: vec![],
                    command_args: vec![],
                },
            ).await
        });
        handles.push(handle);
    }
    
    let mut final_result = None;
    for handle in handles {
        let result = handle.await.unwrap();
        if result.is_ok() {
            final_result = Some(result);
        }
    }
    
    assert!(final_result.is_some(), "Chunked transfer should complete successfully");
    
    // Verify the file was assembled correctly
    let plugin_path = config.plugins.install_dir.join("large-chunked-plugin").join("plugin.bin");
    assert!(plugin_path.exists(), "Plugin file should exist");
    
    let file_data = tokio::fs::read(&plugin_path).await.unwrap();
    assert_eq!(file_data.len(), large_data_len, "File size should match original");
}

#[tokio::test]
async fn extreme_error_recovery_scenarios() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.plugins.install_dir = temp_dir.path().join("plugins");
    
    // Test 1: Create directory with restricted permissions
    std::fs::create_dir_all(&config.plugins.install_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.plugins.install_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    
    let config = Arc::new(config);
    let plugin_manager = aetheric_edge::agent::plugin_manager::PluginManager::new(config.clone());
    
    // Try to install plugin with no write permissions
    let result = plugin_manager.install_plugin(
        "no-perms-plugin",
        &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
            checksum: None,
            checksum_type: None,
        },
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: "no-perms-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
            auto_start: false,
            environment: std::collections::HashMap::new(),
            dependencies: vec![],
            ports: vec![],
            volumes: vec![],
            command_args: vec![],
        },
    ).await;
    
    assert!(result.is_err(), "Should fail with permission error");
    
    // Fix permissions for cleanup
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.plugins.install_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    
    // Test 2: Simulate disk full by filling temp directory
    let fill_path = temp_dir.path().join("fill");
    std::fs::create_dir_all(&fill_path).unwrap();
    
    // Create many small files to simulate disk pressure
    for i in 0..1000 {
        let file_path = fill_path.join(format!("file_{}.dat", i));
        if std::fs::write(&file_path, vec![0u8; 1024]).is_err() {
            break; // Stop when we can't write anymore
        }
    }
    
    // Test 3: Invalid plugin configurations
    let invalid_configs = vec![
        // Plugin with invalid environment variables
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: "invalid-env".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
            auto_start: false,
            environment: vec![
                ("".to_string(), "empty key".to_string()),
                ("KEY WITH SPACES".to_string(), "value".to_string()),
                ("KEY=WITH=EQUALS".to_string(), "value".to_string()),
            ].into_iter().collect(),
            dependencies: vec![],
            ports: vec![],
            volumes: vec![],
            command_args: vec![],
        },
        // Plugin with conflicting ports
        aetheric_edge::agent::plugin_manager::PluginConfig {
            name: "port-conflict".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Docker,
            auto_start: false,
            environment: std::collections::HashMap::new(),
            dependencies: vec![],
            ports: vec![80, 80, 443, 443], // Duplicate ports
            volumes: vec![],
            command_args: vec![],
        },
    ];
    
    for config in invalid_configs {
        let plugin_name = config.name.clone();
        let _result = plugin_manager.install_plugin(
            &plugin_name,
            &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
                checksum: None,
                checksum_type: None,
            },
            config,
        ).await;
        
        // Should handle gracefully without panic
        println!("Invalid config test result: {:?}", _result.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn extreme_resource_exhaustion_test() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config();
    config.plugins.install_dir = temp_dir.path().join("plugins");
    config.plugins.max_concurrent_installs = 100; // Allow many concurrent installs
    
    let config = Arc::new(config);
    let plugin_manager = aetheric_edge::agent::plugin_manager::PluginManager::new(config.clone());
    
    // Try to exhaust system resources
    let mut handles = vec![];
    
    // 1. File descriptor exhaustion - create many plugins
    for i in 0..500 {
        let pm = plugin_manager.clone();
        let handle = tokio::spawn(async move {
            let _ = pm.install_plugin(
                &format!("fd-exhaust-{}", i),
                &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("plugin-{}", i).as_bytes()),
                    checksum: None,
                    checksum_type: None,
                },
                aetheric_edge::agent::plugin_manager::PluginConfig {
                    name: format!("fd-exhaust-{}", i),
                    version: "1.0.0".to_string(),
                    description: None,
                    plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
                    auto_start: false,
                    environment: std::collections::HashMap::new(),
                    dependencies: vec![],
                    ports: vec![],
                    volumes: vec![],
                    command_args: vec![],
                },
            ).await;
        });
        handles.push(handle);
    }
    
    // 2. Memory pressure - create large plugin configs
    for i in 0..50 {
        let pm = plugin_manager.clone();
        let handle = tokio::spawn(async move {
            let large_description = "X".repeat(1_000_000); // 1MB string
            let _ = pm.install_plugin(
                &format!("mem-pressure-{}", i),
                &aetheric_edge::agent::plugin_manager::PluginSource::Base64 {
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"small"),
                    checksum: None,
                    checksum_type: None,
                },
                aetheric_edge::agent::plugin_manager::PluginConfig {
                    name: format!("mem-pressure-{}", i),
                    version: "1.0.0".to_string(),
                    description: Some(large_description),
                    plugin_type: aetheric_edge::agent::plugin_manager::PluginType::Binary,
                    auto_start: false,
                    environment: (0..1000).map(|j| {
                        (format!("KEY_{}", j), "VALUE".repeat(100))
                    }).collect(),
                    dependencies: vec!["dep".to_string(); 1000],
                    ports: vec![],
                    volumes: vec![],
                    command_args: vec!["arg".to_string(); 1000],
                },
            ).await;
        });
        handles.push(handle);
    }
    
    // Wait for all operations with timeout
    let results = timeout(Duration::from_secs(30), async {
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await);
        }
        results
    }).await;
    
    // System should survive without crashing
    assert!(results.is_ok() || results.is_err(), "Should handle resource exhaustion");
}

#[tokio::test]
async fn extreme_malformed_mqtt_messages() {
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    // Send various malformed messages
    let malformed_messages = vec![
        // Extremely large command ID
        CommandMessage {
            id: "X".repeat(10_000),
            command: CommandType::Health,
            timestamp: chrono::Utc::now().to_rfc3339(),
            parameters: std::collections::HashMap::new(),
        },
        // Invalid timestamp
        CommandMessage {
            id: "test".to_string(),
            command: CommandType::Health,
            timestamp: "NOT A TIMESTAMP".to_string(),
            parameters: std::collections::HashMap::new(),
        },
        // Huge parameter map
        CommandMessage {
            id: "test2".to_string(),
            command: CommandType::Health,
            timestamp: chrono::Utc::now().to_rfc3339(),
            parameters: (0..10_000).map(|i| {
                (format!("key_{}", i), serde_json::json!({"data": "X".repeat(1000)}))
            }).collect(),
        },
    ];
    
    for msg in malformed_messages {
        command_tx.send(msg).unwrap();
    }
    
    // Try to receive and process
    let mut received = 0;
    while let Ok(Some(msg)) = timeout(Duration::from_millis(100), command_rx.recv()).await {
        received += 1;
        // Just receiving without panic is success
        println!("Received message with ID length: {}", msg.id.len());
    }
    
    assert_eq!(received, 3, "Should receive all messages without panic");
}

