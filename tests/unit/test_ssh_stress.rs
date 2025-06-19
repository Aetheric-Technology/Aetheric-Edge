use aetheric_edge::agent::ssh_tunnel::{
    SshCommand, SshDataDirection, SshSessionStatus, SshTunnelManager,
};
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;

/// Stress tests for SSH functionality
/// These tests focus on performance, scalability, and system limits

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-stress".to_string(),
            name: Some("Test Stress Gateway".to_string()),
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
            max_sessions: 50, // Higher limit for stress testing
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

async fn create_test_mqtt_client() -> (
    MqttClient,
    mpsc::UnboundedReceiver<aetheric_edge::mqtt::messages::CommandMessage>,
) {
    let (command_sender, command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway-stress".to_string(),
        command_sender,
    )
    .await
    .unwrap();
    (mqtt_client, command_receiver)
}

#[tokio::test]
async fn test_high_frequency_commands() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let start_time = Instant::now();
    let command_count = 1000;

    // Send many rapid commands
    let mut successful_commands = 0;

    for i in 0..command_count {
        // Mix different types of commands
        let command = match i % 4 {
            0 => SshCommand::Connect {
                session_id: format!("rapid-connect-{}", i),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            },
            1 => SshCommand::Heartbeat {
                session_id: format!("rapid-heartbeat-{}", i),
            },
            2 => SshCommand::Data {
                session_id: format!("rapid-data-{}", i),
                data: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"stress test data",
                ),
                direction: SshDataDirection::Up,
            },
            3 => SshCommand::Disconnect {
                session_id: format!("rapid-disconnect-{}", i),
            },
            _ => unreachable!(),
        };

        let response = ssh_manager.handle_ssh_command(command).await;
        if response.is_ok() {
            successful_commands += 1;
        }
    }

    let elapsed = start_time.elapsed();
    let commands_per_second = command_count as f64 / elapsed.as_secs_f64();

    println!(
        "Processed {} commands in {:?} ({:.2} commands/second)",
        command_count, elapsed, commands_per_second
    );

    // Should handle at least most commands successfully
    assert!(
        successful_commands > command_count * 90 / 100,
        "Too many command failures"
    );

    // Should process commands reasonably quickly (at least 100 commands/second)
    assert!(
        commands_per_second > 100.0,
        "Command processing too slow: {:.2} commands/second",
        commands_per_second
    );
}

#[tokio::test]
async fn test_concurrent_session_creation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let concurrent_sessions = 20;
    let mut handles = Vec::new();

    let start_time = Instant::now();

    // Create many concurrent session creation requests
    for i in 0..concurrent_sessions {
        let manager = ssh_manager.clone();

        let handle = tokio::spawn(async move {
            let session_id = format!("concurrent-stress-{}", i);

            let connect_command = SshCommand::Connect {
                session_id: session_id.clone(),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            };

            let start = Instant::now();
            let response = manager.handle_ssh_command(connect_command).await;
            let duration = start.elapsed();

            (session_id, response, duration)
        });

        handles.push(handle);
    }

    // Wait for all concurrent operations
    let mut successful_connections = 0;
    let mut total_duration = Duration::ZERO;
    let mut created_sessions = Vec::new();

    for handle in handles {
        let (session_id, result, duration) = handle.await.unwrap();
        total_duration += duration;

        match result {
            Ok(response) => {
                if matches!(response.status, SshSessionStatus::Connected) {
                    successful_connections += 1;
                    created_sessions.push(session_id);
                }
            }
            Err(_) => {
                // Some failures are acceptable under high concurrency
            }
        }
    }

    let total_elapsed = start_time.elapsed();
    let avg_duration = total_duration / concurrent_sessions;

    println!(
        "Created {} successful sessions out of {} attempts in {:?} (avg: {:?})",
        successful_connections, concurrent_sessions, total_elapsed, avg_duration
    );

    // Clean up successful sessions
    for session_id in created_sessions {
        let disconnect_command = SshCommand::Disconnect { session_id };
        let _response = ssh_manager.handle_ssh_command(disconnect_command).await;
    }

    // Should create some sessions successfully
    assert!(
        successful_connections > 0,
        "No sessions created successfully"
    );

    // Average response time should be reasonable (under 100ms)
    assert!(
        avg_duration < Duration::from_millis(100),
        "Session creation too slow: {:?}",
        avg_duration
    );
}

#[tokio::test]
async fn test_data_throughput_stress() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let session_id = "throughput-test";

    // Create a session first
    let connect_command = SshCommand::Connect {
        session_id: session_id.to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };

    let connect_response = ssh_manager
        .handle_ssh_command(connect_command)
        .await
        .unwrap();

    if matches!(connect_response.status, SshSessionStatus::Connected) {
        let data_packets = 500;
        let packet_size = 1024; // 1KB per packet
        let test_data = vec![b'X'; packet_size];
        let base64_data =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &test_data);

        let start_time = Instant::now();
        let mut successful_packets = 0;

        // Send many data packets rapidly
        for i in 0..data_packets {
            let direction = if i % 2 == 0 {
                SshDataDirection::Up
            } else {
                SshDataDirection::Down
            };

            let data_command = SshCommand::Data {
                session_id: session_id.to_string(),
                data: base64_data.clone(),
                direction,
            };

            let response = ssh_manager.handle_ssh_command(data_command).await;
            if response.is_ok() {
                successful_packets += 1;
            }
        }

        let elapsed = start_time.elapsed();
        let packets_per_second = successful_packets as f64 / elapsed.as_secs_f64();
        let throughput_mbps =
            (successful_packets * packet_size) as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();

        println!(
            "Sent {} packets ({} KB each) in {:?} ({:.2} packets/sec, {:.2} MB/s)",
            successful_packets,
            packet_size / 1024,
            elapsed,
            packets_per_second,
            throughput_mbps
        );

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };
        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();

        // Should handle most packets successfully
        assert!(
            successful_packets > data_packets * 90 / 100,
            "Too many packet failures"
        );

        // Should achieve reasonable throughput (at least 50 packets/second)
        assert!(
            packets_per_second > 50.0,
            "Data throughput too slow: {:.2} packets/second",
            packets_per_second
        );
    }
}

#[tokio::test]
async fn test_session_churn_stress() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let cycles = 50;
    let sessions_per_cycle = 5;

    let start_time = Instant::now();
    let mut total_successful_connections = 0;
    let mut total_successful_disconnections = 0;

    for cycle in 0..cycles {
        let mut cycle_sessions = Vec::new();

        // Create sessions
        for i in 0..sessions_per_cycle {
            let session_id = format!("churn-{}-{}", cycle, i);

            let connect_command = SshCommand::Connect {
                session_id: session_id.clone(),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            };

            let response = ssh_manager
                .handle_ssh_command(connect_command)
                .await
                .unwrap();
            if matches!(response.status, SshSessionStatus::Connected) {
                total_successful_connections += 1;
                cycle_sessions.push(session_id);
            }
        }

        // Send some data to each session
        for session_id in &cycle_sessions {
            let data_command = SshCommand::Data {
                session_id: session_id.clone(),
                data: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"churn test",
                ),
                direction: SshDataDirection::Up,
            };

            let _response = ssh_manager.handle_ssh_command(data_command).await;
        }

        // Disconnect sessions
        for session_id in cycle_sessions {
            let disconnect_command = SshCommand::Disconnect { session_id };

            let response = ssh_manager
                .handle_ssh_command(disconnect_command)
                .await
                .unwrap();
            if !matches!(response.status, SshSessionStatus::Failed) {
                total_successful_disconnections += 1;
            }
        }

        // Verify session count is back to 0
        let session_count = ssh_manager.get_session_count().await;
        assert_eq!(
            session_count, 0,
            "Sessions not cleaned up after cycle {}",
            cycle
        );
    }

    let elapsed = start_time.elapsed();
    let cycles_per_second = cycles as f64 / elapsed.as_secs_f64();

    println!(
        "Completed {} churn cycles ({} sessions each) in {:?} ({:.2} cycles/sec)",
        cycles, sessions_per_cycle, elapsed, cycles_per_second
    );
    println!(
        "Successful connections: {}, disconnections: {}",
        total_successful_connections, total_successful_disconnections
    );

    // Should complete cycles at reasonable speed
    assert!(
        cycles_per_second > 1.0,
        "Session churn too slow: {:.2} cycles/second",
        cycles_per_second
    );

    // Should have some successful operations
    assert!(
        total_successful_connections > 0,
        "No successful connections"
    );
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let initial_session_count = ssh_manager.get_session_count().await;
    assert_eq!(initial_session_count, 0);

    // Create and destroy many sessions to test memory cleanup
    let total_sessions = 100;
    let batch_size = 10;

    for batch in 0..(total_sessions / batch_size) {
        let mut batch_sessions = Vec::new();

        // Create batch of sessions
        for i in 0..batch_size {
            let session_id = format!("memory-test-{}-{}", batch, i);

            let connect_command = SshCommand::Connect {
                session_id: session_id.clone(),
                target_host: Some("127.0.0.1".to_string()),
                target_port: Some(22),
                duration_minutes: Some(30),
            };

            let response = ssh_manager
                .handle_ssh_command(connect_command)
                .await
                .unwrap();
            if matches!(response.status, SshSessionStatus::Connected) {
                batch_sessions.push(session_id);
            }
        }

        // Send data to sessions
        for session_id in &batch_sessions {
            for _ in 0..5 {
                let data_command = SshCommand::Data {
                    session_id: session_id.clone(),
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &vec![0u8; 1024],
                    ),
                    direction: SshDataDirection::Up,
                };

                let _response = ssh_manager.handle_ssh_command(data_command).await;
            }
        }

        // Disconnect all sessions in batch
        for session_id in batch_sessions {
            let disconnect_command = SshCommand::Disconnect { session_id };
            let _response = ssh_manager.handle_ssh_command(disconnect_command).await;
        }

        // Verify cleanup
        let current_session_count = ssh_manager.get_session_count().await;
        assert_eq!(
            current_session_count, 0,
            "Memory leak detected - sessions not cleaned up in batch {}",
            batch
        );
    }

    // Final verification
    let final_session_count = ssh_manager.get_session_count().await;
    assert_eq!(
        final_session_count, 0,
        "Memory leak detected - final session count not zero"
    );
}

#[tokio::test]
async fn test_error_handling_under_stress() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let operations = 200;
    let mut handles = Vec::new();

    // Create many concurrent operations that will mostly fail
    for i in 0..operations {
        let manager = ssh_manager.clone();

        let handle = tokio::spawn(async move {
            let operations = vec![
                // These will fail due to non-existent sessions
                SshCommand::Data {
                    session_id: format!("nonexistent-{}", i),
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        b"test",
                    ),
                    direction: SshDataDirection::Up,
                },
                SshCommand::Heartbeat {
                    session_id: format!("nonexistent-{}", i),
                },
                SshCommand::Disconnect {
                    session_id: format!("nonexistent-{}", i),
                },
                // This might succeed or fail
                SshCommand::Connect {
                    session_id: format!("stress-error-{}", i),
                    target_host: Some("127.0.0.1".to_string()),
                    target_port: Some(22),
                    duration_minutes: Some(30),
                },
            ];

            let mut results = Vec::new();
            for operation in operations {
                let result = manager.handle_ssh_command(operation).await;
                results.push(result);
            }

            results
        });

        handles.push(handle);
    }

    // Wait for all operations and verify they complete without panicking
    let mut total_operations = 0;
    let mut successful_operations = 0;
    let mut failed_operations = 0;

    for handle in handles {
        let results = handle.await.expect("Task should not panic");

        for result in results {
            total_operations += 1;
            match result {
                Ok(response) => {
                    match response.status {
                        SshSessionStatus::Connected => successful_operations += 1,
                        SshSessionStatus::Failed => failed_operations += 1,
                        _ => {} // Other statuses
                    }
                }
                Err(_) => failed_operations += 1,
            }
        }
    }

    println!(
        "Stress test completed: {} total operations, {} successful, {} failed",
        total_operations, successful_operations, failed_operations
    );

    // The key is that all operations completed without panicking
    assert_eq!(total_operations, operations * 4); // 4 operations per task

    // Most operations should fail gracefully (expected due to non-existent sessions)
    assert!(
        failed_operations > total_operations / 2,
        "Expected more graceful failures"
    );

    // System should remain stable - verify we can still perform operations
    let final_test_command = SshCommand::Connect {
        session_id: "final-stability-test".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };

    let final_response = ssh_manager.handle_ssh_command(final_test_command).await;
    assert!(
        final_response.is_ok(),
        "System should remain responsive after stress test"
    );
}

#[tokio::test]
async fn test_long_running_session_stress() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));

    let session_id = "long-running-stress";

    // Create session
    let connect_command = SshCommand::Connect {
        session_id: session_id.to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };

    let connect_response = ssh_manager
        .handle_ssh_command(connect_command)
        .await
        .unwrap();

    if matches!(connect_response.status, SshSessionStatus::Connected) {
        let operations_count = 100;
        let heartbeat_interval = Duration::from_millis(50);

        let start_time = Instant::now();

        // Simulate long-running session with periodic heartbeats and data
        for i in 0..operations_count {
            // Send heartbeat
            let heartbeat_command = SshCommand::Heartbeat {
                session_id: session_id.to_string(),
            };

            let heartbeat_response = ssh_manager
                .handle_ssh_command(heartbeat_command)
                .await
                .unwrap();
            assert_eq!(
                heartbeat_response.status,
                SshSessionStatus::Connected,
                "Heartbeat {} failed",
                i
            );

            // Send some data
            let data_command = SshCommand::Data {
                session_id: session_id.to_string(),
                data: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("Long running data packet {}", i).as_bytes(),
                ),
                direction: if i % 2 == 0 {
                    SshDataDirection::Up
                } else {
                    SshDataDirection::Down
                },
            };

            let _data_response = ssh_manager.handle_ssh_command(data_command).await.unwrap();

            // Small delay to simulate real usage
            tokio::time::sleep(heartbeat_interval).await;
        }

        let elapsed = start_time.elapsed();
        let operations_per_second = operations_count as f64 / elapsed.as_secs_f64();

        println!(
            "Long-running session: {} operations in {:?} ({:.2} ops/sec)",
            operations_count, elapsed, operations_per_second
        );

        // Session should remain active throughout
        let session_count = ssh_manager.get_session_count().await;
        assert_eq!(session_count, 1, "Session should still be active");

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };
        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();

        // Should maintain reasonable performance throughout
        assert!(
            operations_per_second > 10.0,
            "Long-running session performance degraded: {:.2} ops/sec",
            operations_per_second
        );
    }
}
