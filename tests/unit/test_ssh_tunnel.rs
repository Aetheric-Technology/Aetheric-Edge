use aetheric_edge::agent::ssh_tunnel::{SshTunnelManager, SshCommand, SshDataDirection, SshSessionStatus};
use aetheric_edge::config::AethericConfig;
use aetheric_edge::mqtt::client::MqttClient;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;

fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
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
        "test-gateway".to_string(),
        command_sender,
    ).await.unwrap();
    (mqtt_client, command_receiver)
}

#[tokio::test]
async fn test_ssh_tunnel_manager_creation() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test that we can get session count (should be 0 initially)
    let session_count = ssh_manager.get_session_count().await;
    assert_eq!(session_count, 0);
}

#[tokio::test]
async fn test_ssh_connect_command() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    let connect_command = SshCommand::Connect {
        session_id: "test-session-001".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };
    
    let response = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
    
    assert_eq!(response.session_id, "test-session-001");
    // The response should be either Connected or Failed (depending on if SSH server is running)
    assert!(matches!(response.status, SshSessionStatus::Connected | SshSessionStatus::Failed));
    
    if matches!(response.status, SshSessionStatus::Connected) {
        assert!(response.local_port.is_some());
        let local_port = response.local_port.unwrap();
        assert!(local_port >= 10000 && local_port < 11000);
    }
}

#[tokio::test]
async fn test_ssh_connect_duplicate_session() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    let connect_command = SshCommand::Connect {
        session_id: "duplicate-session".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };
    
    // First connection attempt
    let response1 = ssh_manager.handle_ssh_command(connect_command.clone()).await.unwrap();
    
    // Second connection attempt with same session ID should fail
    let response2 = ssh_manager.handle_ssh_command(connect_command).await.unwrap();
    
    if matches!(response1.status, SshSessionStatus::Connected) {
        assert_eq!(response2.status, SshSessionStatus::Failed);
        assert_eq!(response2.message, "Session already exists");
    }
}

#[tokio::test]
async fn test_ssh_disconnect_command() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Try to disconnect non-existent session
    let disconnect_command = SshCommand::Disconnect {
        session_id: "non-existent-session".to_string(),
    };
    
    let response = ssh_manager.handle_ssh_command(disconnect_command).await.unwrap();
    
    assert_eq!(response.session_id, "non-existent-session");
    assert_eq!(response.status, SshSessionStatus::Failed);
    assert_eq!(response.message, "Session not found");
}

#[tokio::test]
async fn test_ssh_heartbeat_command() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test heartbeat for non-existent session
    let heartbeat_command = SshCommand::Heartbeat {
        session_id: "non-existent-session".to_string(),
    };
    
    let response = ssh_manager.handle_ssh_command(heartbeat_command).await.unwrap();
    
    assert_eq!(response.session_id, "non-existent-session");
    assert_eq!(response.status, SshSessionStatus::Failed);
    assert_eq!(response.message, "Session not found");
}

#[tokio::test]
async fn test_ssh_data_command() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Test data command for non-existent session
    let data_command = SshCommand::Data {
        session_id: "non-existent-session".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test data"),
        direction: SshDataDirection::Up,
    };
    
    let response = ssh_manager.handle_ssh_command(data_command).await.unwrap();
    
    assert_eq!(response.session_id, "non-existent-session");
    assert_eq!(response.status, SshSessionStatus::Failed);
    assert_eq!(response.message, "Session not found");
}

#[tokio::test]
async fn test_ssh_max_sessions_limit() {
    let mut config = create_test_config();
    config.ssh.max_sessions = 1; // Set max sessions to 1
    let config = Arc::new(config);
    
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // First session
    let connect_command1 = SshCommand::Connect {
        session_id: "session-1".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };
    
    let response1 = ssh_manager.handle_ssh_command(connect_command1).await.unwrap();
    
    // Second session should fail due to max sessions limit
    let connect_command2 = SshCommand::Connect {
        session_id: "session-2".to_string(),
        target_host: Some("127.0.0.1".to_string()),
        target_port: Some(22),
        duration_minutes: Some(30),
    };
    
    let response2 = ssh_manager.handle_ssh_command(connect_command2).await.unwrap();
    
    if matches!(response1.status, SshSessionStatus::Connected) {
        assert_eq!(response2.status, SshSessionStatus::Failed);
        assert!(response2.message.contains("Maximum number of SSH sessions reached"));
    }
}

#[tokio::test]
async fn test_ssh_disabled_config() {
    let mut config = create_test_config();
    config.ssh.enabled = false;
    let config = Arc::new(config);
    
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Starting SSH manager should succeed but log a warning
    let result = ssh_manager.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ssh_session_serialization() {
    use aetheric_edge::agent::ssh_tunnel::SshSession;
    
    let session = SshSession {
        session_id: "test-session".to_string(),
        client_id: "test-client".to_string(),
        created_at: 1634567890,
        last_activity: 1634567890,
        status: SshSessionStatus::Connected,
        local_port: 10001,
        target_host: "127.0.0.1".to_string(),
        target_port: 22,
    };
    
    // Test serialization to JSON
    let json = serde_json::to_string(&session).unwrap();
    assert!(json.contains("test-session"));
    assert!(json.contains("connected"));
    
    // Test deserialization from JSON
    let deserialized: SshSession = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.session_id, session.session_id);
    assert_eq!(deserialized.local_port, session.local_port);
    assert!(matches!(deserialized.status, SshSessionStatus::Connected));
}

#[tokio::test]
async fn test_get_active_sessions() {
    let config = Arc::new(create_test_config());
    let (mqtt_client, _) = create_test_mqtt_client().await;
    let mqtt_client_arc = Arc::new(mqtt_client);
    
    let ssh_manager = SshTunnelManager::new(config.clone(), mqtt_client_arc);
    
    // Initially no sessions
    let sessions = ssh_manager.get_active_sessions().await.unwrap();
    assert_eq!(sessions.len(), 0);
    
    // Note: We can't easily test with actual sessions in unit tests
    // without starting actual TCP servers, but the structure is tested
}