use aetheric_edge::agent::ssh_tunnel::{
    SshCommand, SshDataDirection, SshSessionStatus, SshTunnelManager,
};
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// Tests for SSH session lifecycle management
/// These tests focus on session creation, state transitions, and cleanup

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-sessions".to_string(),
            name: Some("Test Sessions Gateway".to_string()),
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
            max_sessions: 10,
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
        "test-gateway-sessions".to_string(),
        command_sender,
    )
    .await
    .unwrap();
    (mqtt_client, command_receiver)
}

#[tokio::test]
async fn test_session_lifecycle_complete() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "lifecycle-test-session";

    // 1. Initial state - no sessions
    let initial_count = ssh_manager.get_session_count().await;
    assert_eq!(initial_count, 0);

    // 2. Create session
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
    assert_eq!(connect_response.session_id, session_id);

    // If connection succeeds, test the full lifecycle
    if matches!(connect_response.status, SshSessionStatus::Connected) {
        // 3. Session should be active
        let active_count = ssh_manager.get_session_count().await;
        assert_eq!(active_count, 1);

        // 4. Send heartbeat
        let heartbeat_command = SshCommand::Heartbeat {
            session_id: session_id.to_string(),
        };

        let heartbeat_response = ssh_manager
            .handle_ssh_command(heartbeat_command)
            .await
            .unwrap();
        assert_eq!(heartbeat_response.status, SshSessionStatus::Connected);

        // 5. Send data
        let data_command = SshCommand::Data {
            session_id: session_id.to_string(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test data"),
            direction: SshDataDirection::Up,
        };

        let data_response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
        assert_eq!(data_response.session_id, session_id);

        // 6. Disconnect session
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
        assert_eq!(disconnect_response.session_id, session_id);

        // 7. Session should be gone
        let final_count = ssh_manager.get_session_count().await;
        assert_eq!(final_count, 0);
    }
}

#[tokio::test]
async fn test_session_state_transitions() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "state-transition-test";

    // Test invalid state transitions

    // 1. Try to send data to non-existent session
    let data_command = SshCommand::Data {
        session_id: session_id.to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
        direction: SshDataDirection::Up,
    };

    let data_response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
    assert_eq!(data_response.status, SshSessionStatus::Failed);
    assert_eq!(data_response.message, "Session not found");

    // 2. Try to send heartbeat to non-existent session
    let heartbeat_command = SshCommand::Heartbeat {
        session_id: session_id.to_string(),
    };

    let heartbeat_response = ssh_manager
        .handle_ssh_command(heartbeat_command)
        .await
        .unwrap();
    assert_eq!(heartbeat_response.status, SshSessionStatus::Failed);
    assert_eq!(heartbeat_response.message, "Session not found");

    // 3. Try to disconnect non-existent session
    let disconnect_command = SshCommand::Disconnect {
        session_id: session_id.to_string(),
    };

    let disconnect_response = ssh_manager
        .handle_ssh_command(disconnect_command)
        .await
        .unwrap();
    assert_eq!(disconnect_response.status, SshSessionStatus::Failed);
    assert_eq!(disconnect_response.message, "Session not found");
}

#[tokio::test]
async fn test_multiple_sessions_management() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    // Create multiple sessions
    let session_ids = vec!["session-1", "session-2", "session-3"];
    let mut successful_sessions = Vec::new();

    for session_id in &session_ids {
        let connect_command = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };

        let response = ssh_manager
            .handle_ssh_command(connect_command)
            .await
            .unwrap();
        if matches!(response.status, SshSessionStatus::Connected) {
            successful_sessions.push(session_id);
        }
    }

    // If we have successful sessions, test management
    if !successful_sessions.is_empty() {
        // Check session count
        let active_count = ssh_manager.get_session_count().await;
        assert_eq!(active_count, successful_sessions.len());

        // Get active sessions
        let active_sessions = ssh_manager.get_active_sessions().await.unwrap();
        assert_eq!(active_sessions.len(), successful_sessions.len());

        // Verify session data
        for session in &active_sessions {
            assert!(successful_sessions.contains(&&session.session_id.as_str()));
            assert_eq!(session.target_host, "127.0.0.1");
            assert_eq!(session.target_port, 22);
            assert!(matches!(session.status, SshSessionStatus::Connected));
        }

        // Disconnect all sessions
        for session_id in &successful_sessions {
            let disconnect_command = SshCommand::Disconnect {
                session_id: session_id.to_string(),
            };

            let _response = ssh_manager
                .handle_ssh_command(disconnect_command)
                .await
                .unwrap();
        }

        // Verify all sessions are gone
        let final_count = ssh_manager.get_session_count().await;
        assert_eq!(final_count, 0);
    }
}

#[tokio::test]
async fn test_session_data_handling() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "data-handling-test";

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
        // Test various data sizes and types
        let test_data = vec![
            b"small data".to_vec(),
            b"Hello, World! This is a test message.".to_vec(),
            vec![0u8; 1024],                       // 1KB of zeros
            vec![255u8; 512],                      // 512B of 0xFF
            b"Line 1\nLine 2\nLine 3\n".to_vec(),  // Multi-line data
            "Unicode: 🚀🔥💻".as_bytes().to_vec(), // Unicode data
        ];

        for (i, data) in test_data.iter().enumerate() {
            // Test upstream data
            let up_command = SshCommand::Data {
                session_id: session_id.to_string(),
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
                direction: SshDataDirection::Up,
            };

            let up_response = ssh_manager.handle_ssh_command(up_command).await.unwrap();
            assert_eq!(
                up_response.session_id, session_id,
                "Failed on data test {}",
                i
            );

            // Test downstream data
            let down_command = SshCommand::Data {
                session_id: session_id.to_string(),
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
                direction: SshDataDirection::Down,
            };

            let down_response = ssh_manager.handle_ssh_command(down_command).await.unwrap();
            assert_eq!(
                down_response.session_id, session_id,
                "Failed on data test {}",
                i
            );
        }

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_session_heartbeat_mechanism() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "heartbeat-test";

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
        // Send multiple heartbeats
        for i in 0..5 {
            let heartbeat_command = SshCommand::Heartbeat {
                session_id: session_id.to_string(),
            };

            let heartbeat_response = ssh_manager
                .handle_ssh_command(heartbeat_command)
                .await
                .unwrap();
            assert_eq!(heartbeat_response.session_id, session_id);
            assert_eq!(
                heartbeat_response.status,
                SshSessionStatus::Connected,
                "Heartbeat {} failed",
                i
            );

            // Small delay between heartbeats
            sleep(Duration::from_millis(100)).await;
        }

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_session_port_allocation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    // Create multiple sessions and check port allocation
    let mut allocated_ports = Vec::new();
    let session_count = 3;

    for i in 0..session_count {
        let session_id = format!("port-test-{}", i);

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
            if let Some(local_port) = response.local_port {
                // Port should be in the expected range (10000-10999)
                assert!(
                    (10000..11000).contains(&local_port),
                    "Port {} out of range",
                    local_port
                );

                // Port should be unique
                assert!(
                    !allocated_ports.contains(&local_port),
                    "Duplicate port {} allocated",
                    local_port
                );

                allocated_ports.push(local_port);
            }
        }
    }

    // Clean up all sessions
    for i in 0..session_count {
        let session_id = format!("port-test-{}", i);

        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.clone(),
        };

        let _response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_session_metadata() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "metadata-test";

    // Create session
    let connect_command = SshCommand::Connect {
        session_id: session_id.to_string(),
        target_host: Some("192.168.1.100".to_string()),
        target_port: Some(2222),
        duration_minutes: Some(60),
    };

    let connect_response = ssh_manager
        .handle_ssh_command(connect_command)
        .await
        .unwrap();

    if matches!(connect_response.status, SshSessionStatus::Connected) {
        // Get session details
        let active_sessions = ssh_manager.get_active_sessions().await.unwrap();
        assert_eq!(active_sessions.len(), 1);

        let session = &active_sessions[0];

        // Verify session metadata
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_id, "test-gateway-sessions");
        assert_eq!(session.target_host, "192.168.1.100");
        assert_eq!(session.target_port, 2222);
        assert!(matches!(session.status, SshSessionStatus::Connected));

        // Verify timestamps
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Created time should be recent (within last 5 seconds)
        assert!(
            current_time - session.created_at < 5,
            "Created time seems wrong"
        );

        // Last activity should be recent
        assert!(
            current_time - session.last_activity < 5,
            "Last activity time seems wrong"
        );

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_session_duplicate_handling() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "duplicate-test";

    // Create first session
    let connect_command1 = SshCommand::Connect {
        session_id: session_id.to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };

    let response1 = ssh_manager
        .handle_ssh_command(connect_command1)
        .await
        .unwrap();

    if matches!(response1.status, SshSessionStatus::Connected) {
        // Try to create duplicate session
        let connect_command2 = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };

        let response2 = ssh_manager
            .handle_ssh_command(connect_command2)
            .await
            .unwrap();

        // Second attempt should fail
        assert_eq!(response2.status, SshSessionStatus::Failed);
        assert_eq!(response2.message, "Session already exists");

        // Should still have only one session
        let session_count = ssh_manager.get_session_count().await;
        assert_eq!(session_count, 1);

        // Clean up
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let _disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_session_cleanup_on_disconnect() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);

    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);

    let session_id = "cleanup-test";

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
        // Verify session exists
        let count_before = ssh_manager.get_session_count().await;
        assert_eq!(count_before, 1);

        // Disconnect session
        let disconnect_command = SshCommand::Disconnect {
            session_id: session_id.to_string(),
        };

        let disconnect_response = ssh_manager
            .handle_ssh_command(disconnect_command)
            .await
            .unwrap();
        assert_eq!(disconnect_response.session_id, session_id);

        // Verify session is cleaned up
        let count_after = ssh_manager.get_session_count().await;
        assert_eq!(count_after, 0);

        // Try to interact with disconnected session
        let heartbeat_command = SshCommand::Heartbeat {
            session_id: session_id.to_string(),
        };

        let heartbeat_response = ssh_manager
            .handle_ssh_command(heartbeat_command)
            .await
            .unwrap();
        assert_eq!(heartbeat_response.status, SshSessionStatus::Failed);
        assert_eq!(heartbeat_response.message, "Session not found");
    }
}
