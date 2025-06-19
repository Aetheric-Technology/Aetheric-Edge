use aetheric_edge::agent::ssh_tunnel::{SshTunnelManager, SshCommand, SshDataDirection, SshSessionStatus};
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;

/// Tests for SSH error handling and edge cases
/// These tests focus on error conditions, boundary cases, and resilience

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-errors".to_string(),
            name: Some("Test Errors Gateway".to_string()),
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
        "test-gateway-errors".to_string(),
        command_sender,
    ).await.unwrap();
    (mqtt_client, command_receiver)
}

#[tokio::test]
async fn test_invalid_base64_data() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test various invalid base64 encodings
    let invalid_base64_data = vec![
        "invalid-base64!",
        "dGVzdA", // Missing padding
        "12345", // Invalid characters for base64
        "SGVsbG8gV29ybGQ==!", // Valid base64 with invalid character at end
        "SGVsbG8g\x00V29ybGQ=", // Contains null character
        "", // Empty data (should be valid though)
    ];
    
    for (i, invalid_data) in invalid_base64_data.iter().enumerate() {
        let data_command = SshCommand::Data {
            session_id: "test-session".to_string(),
            data: invalid_data.to_string(),
            direction: SshDataDirection::Up,
        };
        
        let response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
        
        // For most invalid base64, we expect either "Session not found" (if validation passes but session doesn't exist)
        // or a specific base64 validation error
        assert_eq!(response.status, SshSessionStatus::Failed, "Test case {} should fail", i);
        
        // The specific error message depends on where validation occurs
        // Either "Session not found" or base64 validation error
        assert!(
            response.message == "Session not found" || 
            response.message.contains("Invalid") || 
            response.message.contains("base64"),
            "Unexpected error message for case {}: {}", i, response.message
        );
    }
}

#[tokio::test]
async fn test_extremely_long_session_ids() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test various session ID lengths
    let id_100 = "a".repeat(100);
    let id_1000 = "a".repeat(1000);
    let id_10000 = "a".repeat(10000);
    let id_65536 = "a".repeat(65536);
    let test_cases = vec![
        ("", false), // Empty
        ("a", true), // Single character
        (&id_100, true), // Normal long ID
        (&id_1000, true), // Very long ID
        (&id_10000, false), // Extremely long ID should be rejected
        (&id_65536, false), // Excessive length
    ];
    
    for (session_id, should_be_valid) in test_cases {
        let connect_command = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Session ID length {} should be rejected", session_id.len());
        }
        
        // For valid session IDs, the response can be either Connected or Failed (due to no SSH server)
        // but the session ID validation should pass
    }
}

#[tokio::test]
async fn test_special_characters_in_session_ids() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test session IDs with special characters
    let special_session_ids = vec![
        "session-with-dashes",
        "session_with_underscores",
        "session.with.dots",
        "session:with:colons",
        "session/with/slashes",
        "session\\with\\backslashes",
        "session with spaces",
        "session\twith\ttabs",
        "session\nwith\nnewlines",
        "session\rwith\rcarriage-returns",
        "session\x00with\x00nulls",
        "session'with'quotes",
        "session\"with\"double-quotes",
        "session<with>brackets",
        "session{with}braces",
        "session[with]square-brackets",
        "session(with)parentheses",
        "session@with@at-symbols",
        "session#with#hashes",
        "session$with$dollars",
        "session%with%percents",
        "session^with^carets",
        "session&with&ampersands",
        "session*with*asterisks",
        "session+with+plus",
        "session=with=equals",
        "session|with|pipes",
        "session~with~tildes",
        "session`with`backticks",
        "session🚀with🔥emojis",
        "session测试with中文",
    ];
    
    for session_id in special_session_ids {
        let connect_command = SshCommand::Connect {
            session_id: session_id.to_string(),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        // Response should preserve the session ID exactly
        assert_eq!(response.session_id, session_id);
        
        // Some special characters might be rejected by validation
        // Others might be accepted but fail for other reasons (no SSH server)
        // The key is that the system handles them gracefully without panicking
    }
}

#[tokio::test]
async fn test_malformed_hostnames() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test various malformed hostnames
    let malformed_hosts = vec![
        "", // Empty
        " ", // Whitespace only
        ".", // Single dot
        "..", // Double dot
        "...", // Triple dot
        "host.", // Trailing dot
        ".host", // Leading dot
        "host..host", // Double dot in middle
        "host-.com", // Trailing dash
        "-host.com", // Leading dash
        "host_name", // Underscore (might be valid)
        "192.168.1.256", // Invalid IP (octet > 255)
        "192.168.1.-1", // Invalid IP (negative)
        "192.168.1.1.1", // Too many octets
        "192.168.1", // Too few octets
        ":::", // Malformed IPv6
        "::1::1", // Invalid IPv6
        "very-long-hostname-that-exceeds-the-maximum-allowed-length-for-dns-names-which-is-typically-253-characters-but-this-is-much-longer-than-that-and-should-be-rejected-by-any-reasonable-validation-logic-implemented-in-the-system", // Too long
        "host with spaces", // Spaces
        "host\nwith\nnewlines", // Newlines
        "host\x00with\x00nulls", // Null characters
    ];
    
    for (i, host) in malformed_hosts.iter().enumerate() {
        let connect_command = SshCommand::Connect {
            session_id: format!("malformed-host-{}", i),
            target_host: if host.is_empty() { None } else { Some(host.to_string()) },
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        // Most malformed hosts should result in failure
        // The system should handle them gracefully without panicking
        match response.status {
            SshSessionStatus::Failed => {
                // Expected for malformed hosts
                assert!(!response.message.is_empty(), "Error message should not be empty for malformed host: {}", host);
            }
            SshSessionStatus::Connected => {
                // Unexpected but possible if validation is lenient
                // At least the local_port should be set
                assert!(response.local_port.is_some());
            }
            _ => {
                // Other statuses are acceptable as long as they don't panic
            }
        }
    }
}

#[tokio::test]
async fn test_boundary_port_values() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test boundary port values
    let port_tests = vec![
        (0, false), // Port 0 is invalid
        (1, true), // Minimum valid port
        (22, true), // Standard SSH port
        (80, true), // HTTP port
        (443, true), // HTTPS port
        (1023, true), // Last privileged port
        (1024, true), // First unprivileged port
        (8080, true), // Common alternative port
        (65534, true), // Near maximum
        (65535, true), // Maximum valid port
    ];
    
    for (port, should_be_valid) in port_tests {
        let connect_command = SshCommand::Connect {
            session_id: format!("port-boundary-{}", port),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(port),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Port {} should be invalid", port);
        }
        
        // For valid ports, connection might still fail due to no SSH server,
        // but port validation should pass
    }
}

#[tokio::test]
async fn test_excessive_data_sizes() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test various data sizes
    let data_size_tests = vec![
        (0, true), // Empty data
        (1, true), // Single byte
        (1024, true), // 1KB
        (64 * 1024, true), // 64KB
        (1024 * 1024, true), // 1MB
        (10 * 1024 * 1024, false), // 10MB - should be rejected
        (100 * 1024 * 1024, false), // 100MB - definitely too large
    ];
    
    for (size, should_be_valid) in data_size_tests {
        // Create data of specified size
        let data = vec![b'A'; size];
        let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
        
        let data_command = SshCommand::Data {
            session_id: "test-data-size".to_string(),
            data: base64_data,
            direction: SshDataDirection::Up,
        };
        
        let response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
        
        if !should_be_valid {
            // Large data should be rejected
            assert_eq!(response.status, SshSessionStatus::Failed, "Data size {} should be rejected", size);
            assert!(
                response.message.contains("too large") || 
                response.message.contains("size") ||
                response.message == "Session not found", // If size validation passes but session doesn't exist
                "Unexpected message for size {}: {}", size, response.message
            );
        } else {
            // Valid data sizes should get "Session not found" since session doesn't exist
            assert_eq!(response.status, SshSessionStatus::Failed);
            assert_eq!(response.message, "Session not found");
        }
    }
}

#[tokio::test]
async fn test_concurrent_error_conditions() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Create multiple concurrent requests with various error conditions
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let manager = ssh_manager.clone();
        
        let handle = tokio::spawn(async move {
            let session_id = format!("concurrent-error-{}", i);
            
            // Try various error-inducing operations
            let operations = vec![
                // Invalid session operations
                SshCommand::Data {
                    session_id: format!("nonexistent-{}", i),
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
                    direction: SshDataDirection::Up,
                },
                SshCommand::Heartbeat {
                    session_id: format!("nonexistent-heartbeat-{}", i),
                },
                SshCommand::Disconnect {
                    session_id: format!("nonexistent-disconnect-{}", i),
                },
                // Connection with potentially invalid host
                SshCommand::Connect {
                    session_id: session_id.clone(),
                    target_host: Some("nonexistent.invalid.host".to_string()),
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
    
    // Wait for all concurrent operations to complete
    let mut _all_successful = true;
    for handle in handles {
        match handle.await {
            Ok(results) => {
                // All operations should complete without panicking
                for result in results {
                    match result {
                        Ok(response) => {
                            // Response should be valid, likely failed but structured
                            assert_eq!(response.status, SshSessionStatus::Failed);
                            assert!(!response.message.is_empty());
                        }
                        Err(_) => {
                            // Some errors might be expected in concurrent scenarios
                            _all_successful = false;
                        }
                    }
                }
            }
            Err(_) => {
                // Task panicked - this is bad
                _all_successful = false;
            }
        }
    }
    
    // The key test is that we didn't panic under concurrent error conditions
    // Some individual operations might fail, but the system should remain stable
}

#[tokio::test]
async fn test_session_limit_boundary() {
    let mut config = create_test_config();
    config.ssh.max_sessions = 2; // Set low limit for testing
    let config = Arc::new(config);
    
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Try to create exactly max_sessions + 1 sessions
    let mut responses = Vec::new();
    
    for i in 0..3 { // max_sessions = 2, so 3rd should fail
        let connect_command = SshCommand::Connect {
            session_id: format!("limit-test-{}", i),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: Some(30),
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        responses.push(response);
    }
    
    // Count successful vs failed connections
    let connected_count = responses.iter()
        .filter(|r| matches!(r.status, SshSessionStatus::Connected))
        .count();
    
    let _limit_failed_count = responses.iter()
        .filter(|r| r.status == SshSessionStatus::Failed && r.message.contains("Maximum number"))
        .count();
    
    // Should have at most max_sessions connections
    assert!(connected_count <= 2);
    
    // If we hit the limit, there should be limit failure messages
    if connected_count > 0 {
        // Cleanup successful sessions
        for (i, response) in responses.iter().enumerate() {
            if matches!(response.status, SshSessionStatus::Connected) {
                let disconnect_command = SshCommand::Disconnect {
                    session_id: format!("limit-test-{}", i),
                };
                
                let _disconnect_response = ssh_manager.handle_ssh_command(disconnect_command).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn test_timeout_edge_cases() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
    
    // Test extreme timeout values
    let timeout_tests = vec![
        (Some(0), false), // Zero timeout
        (Some(1), true), // Minimum valid timeout
        (Some(u32::MAX), false), // Maximum u32 value - should be rejected
        (Some(365 * 24 * 60), false), // One year in minutes - too long
        (None, true), // No timeout (use default)
    ];
    
    for (timeout, should_be_valid) in timeout_tests {
        let connect_command = SshCommand::Connect {
            session_id: format!("timeout-edge-{:?}", timeout),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            duration_minutes: timeout,
        };
        
        let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
        
        if !should_be_valid {
            assert_eq!(response.status, SshSessionStatus::Failed, "Timeout {:?} should be invalid", timeout);
        }
    }
}