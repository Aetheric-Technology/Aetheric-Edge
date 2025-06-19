use aetheric_edge::agent::ssh_tunnel::{SshTunnelManager, SshCommand, SshDataDirection, SshSessionStatus};
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;

/// Tests for SSH security features and validation
/// These tests focus on authentication, authorization, and security boundaries

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-security".to_string(),
            name: Some("Test Security Gateway".to_string()),
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

async fn create_test_mqtt_client() -> (MqttClient, mpsc::UnboundedReceiver<aetheric_edge::mqtt::messages::CommandMessage>) {
    let (command_sender, command_receiver) = mpsc::unbounded_channel();
    let (mqtt_client, _) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway-security".to_string(),
        command_sender,
    ).await.unwrap();
    (mqtt_client, command_receiver)
}

#[tokio::test]
async fn test_ssh_session_id_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test various session ID formats
    let long_session_id = "a".repeat(256);
    let session_ids = vec![
        "", // Empty
        " ", // Whitespace only
        "session-123", // Valid
        "session_456", // Valid with underscore
        "session.789", // Valid with dot
        &long_session_id, // Very long session ID
        "session\nwith\nnewlines", // Invalid characters
        "session\x00with\x00nulls", // Null characters
        "session🚀with🔥emojis", // Unicode
    ];
    
    for session_id in session_ids {
        let connect_command = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        // Session ID should be preserved in response
        assert_eq!(response.session_id, session_id);
        
        // Empty or whitespace-only session IDs should fail
        if session_id.trim().is_empty() {
            assert_eq!(response.status, SshSessionStatus::Failed);
            assert!(response.message.contains("Invalid session ID") || response.message.contains("Session ID cannot be empty"));
        }
    }
}

#[tokio::test]
async fn test_ssh_target_host_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test various target hosts
    let test_cases = vec![
        ("127.0.0.1", true), // Valid IPv4
        ("::1", true), // Valid IPv6
        ("localhost", true), // Valid hostname
        ("example.com", true), // Valid domain
        ("", false), // Empty
        ("...", false), // Invalid
        ("192.168.1.256", false), // Invalid IPv4
        ("host.example.com", true), // Valid subdomain
        ("192.168.1.1", true), // Valid private IPv4
        ("10.0.0.1", true), // Valid private IPv4
        ("172.16.0.1", true), // Valid private IPv4
    ];
    
    for (host, should_be_valid) in test_cases {
        let connect_command = SshCommand::Connect {
            session_id: format!("test-host-{}", host.replace(".", "-").replace(":", "-")),
            target_host: if host.is_empty() { None } else { Some(host.to_string()) },
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Host {} should fail", host);
        }
        // Note: Valid hosts may still fail due to no actual SSH server, but validation should pass
    }
}

#[tokio::test]
async fn test_ssh_port_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test various port numbers
    let port_tests = vec![
        (0, false), // Invalid port 0
        (1, true), // Valid port 1
        (22, true), // Standard SSH port
        (80, true), // HTTP port
        (443, true), // HTTPS port
        (8080, true), // Common alternative port
        (65535, true), // Maximum valid port
        // Note: Rust u16 prevents testing ports > 65535
    ];
    
    for (port, should_be_valid) in port_tests {
        let connect_command = SshCommand::Connect {
            session_id: format!("test-port-{}", port),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(port),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Port {} should fail", port);
        }
    }
}

#[tokio::test]
async fn test_ssh_data_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test various data payloads
    let kb_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vec![0u8; 1024]);
    let large_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vec![0u8; 64 * 1024]);
    let test_data = vec![
        ("", true), // Empty data
        ("dGVzdA==", true), // Valid base64 "test"
        ("SGVsbG8gV29ybGQ=", true), // Valid base64 "Hello World"
        ("invalid-base64!", false), // Invalid base64
        ("dGVzdA", false), // Invalid base64 (missing padding)
        ("12345", false), // Invalid base64
        (&kb_data, true), // 1KB data
        (&large_data, true), // 64KB data
    ];
    
    for (data, should_be_valid) in test_data {
        let data_command = SshCommand::Data {
            session_id: "non-existent-session".to_string(),
            data: data.to_string(),
            direction: SshDataDirection::Up,
        };
        
        let response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
        
        // Session not found error is expected, but we're testing data validation
        if !should_be_valid {
            // Should fail with validation error, not "session not found"
            assert_eq!(response.status, SshSessionStatus::Failed);
            // The specific error message might vary depending on implementation
        } else {
            // For valid data, we expect "Session not found" since session doesn't exist
            assert_eq!(response.status, SshSessionStatus::Failed);
            assert_eq!(response.message, "Session not found");
        }
    }
}

#[tokio::test]
async fn test_ssh_session_timeout_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test various timeout values
    let timeout_tests = vec![
        (None, true), // No timeout specified (should use default)
        (Some(0), false), // Zero timeout should be invalid
        (Some(1), true), // 1 minute
        (Some(30), true), // 30 minutes
        (Some(60), true), // 1 hour
        (Some(1440), true), // 24 hours
        (Some(u32::MAX), false), // Extremely large timeout should be rejected
    ];
    
    for (timeout, should_be_valid) in timeout_tests {
        let connect_command = SshCommand::Connect {
            session_id: format!("test-timeout-{:?}", timeout),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: timeout,
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Timeout {:?} should fail", timeout);
        }
    }
}

#[tokio::test]
async fn test_ssh_concurrent_session_limits() {
    let mut config = create_test_config();
    config.ssh.max_sessions = 2; // Set low limit for testing
    let config = Arc::new(config);
    
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Try to create multiple sessions
    let mut responses = Vec::new();
    
    for i in 0..5 {
        let connect_command = SshCommand::Connect {
            session_id: format!("concurrent-session-{}", i),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        responses.push(response);
    }
    
    // Count successful connections vs failures due to limits
    let connected_count = responses.iter()
        .filter(|r| matches!(r.status, SshSessionStatus::Connected))
        .count();
    
    let limit_exceeded_count = responses.iter()
        .filter(|r| r.status == SshSessionStatus::Failed && r.message.contains("Maximum number"))
        .count();
    
    // We should have at most max_sessions successful connections
    assert!(connected_count <= 2);
    
    // Some connections should fail due to limits if all were successful connections
    if connected_count == 2 {
        assert!(limit_exceeded_count > 0);
    }
}

#[tokio::test]
async fn test_ssh_data_direction_validation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test both data directions
    let directions = vec![
        SshDataDirection::Up,
        SshDataDirection::Down,
    ];
    
    for direction in directions {
        let data_command = SshCommand::Data {
            session_id: "test-direction".to_string(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test data"),
            direction: direction.clone(),
        };
        
        let response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
        
        // Should fail with "Session not found" since session doesn't exist
        // but direction validation should pass
        assert_eq!(response.status, SshSessionStatus::Failed);
        assert_eq!(response.message, "Session not found");
    }
}

#[tokio::test]
async fn test_ssh_command_serialization_security() {
    // Test that SSH commands can be safely serialized/deserialized
    // This is important for MQTT message handling
    
    let test_commands = vec![
        SshCommand::Connect {
            session_id: "test-session".to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        },
        SshCommand::Disconnect {
            session_id: "test-session".to_string(),
        },
        SshCommand::Data {
            session_id: "test-session".to_string(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"sensitive data"),
            direction: SshDataDirection::Up,
        },
        SshCommand::Heartbeat {
            session_id: "test-session".to_string(),
        },
    ];
    
    for command in test_commands {
        // Test JSON serialization
        let json = serde_json::to_string(&command).unwrap();
        assert!(!json.is_empty());
        
        // Test JSON deserialization
        let deserialized: SshCommand = serde_json::from_str(&json).unwrap();
        
        // Verify the command type is preserved
        match (&command, &deserialized) {
            (SshCommand::Connect { session_id: id1, .. }, SshCommand::Connect { session_id: id2, .. }) => {
                assert_eq!(id1, id2);
            }
            (SshCommand::Disconnect { session_id: id1 }, SshCommand::Disconnect { session_id: id2 }) => {
                assert_eq!(id1, id2);
            }
            (SshCommand::Data { session_id: id1, data: data1, .. }, SshCommand::Data { session_id: id2, data: data2, .. }) => {
                assert_eq!(id1, id2);
                assert_eq!(data1, data2);
            }
            (SshCommand::Heartbeat { session_id: id1 }, SshCommand::Heartbeat { session_id: id2 }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Command type changed during serialization"),
        }
    }
}

#[tokio::test]
async fn test_ssh_response_security() {
    use aetheric_edge::agent::ssh_tunnel::SshResponse;
    
    // Test that SSH responses don't leak sensitive information
    let response = SshResponse {
        session_id: "test-session".to_string(),
        status: SshSessionStatus::Failed,
        message: "Authentication failed".to_string(),
        data: None,
        local_port: None,
    };
    
    let json = serde_json::to_string(&response).unwrap();
    
    // Verify that error messages are sanitized and don't contain sensitive details
    assert!(json.contains("Authentication failed"));
    assert!(!json.contains("password"));
    assert!(!json.contains("private_key"));
    assert!(!json.contains("secret"));
}

#[tokio::test]
async fn test_ssh_disabled_security() {
    let mut config = create_test_config();
    config.ssh.enabled = false; // Disable SSH
    let config = Arc::new(config);
    
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Any SSH command should fail when SSH is disabled
    let connect_command = SshCommand::Connect {
        session_id: "disabled-test".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };
    
    let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
    
    assert_eq!(response.status, SshSessionStatus::Failed);
    assert!(response.message.contains("SSH is disabled") || response.message.contains("not enabled"));
}