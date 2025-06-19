use aetheric_edge::config::AethericConfig;
use std::collections::HashMap;
use tempfile::TempDir;

/// Create a test configuration for unit tests
pub fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    create_test_config_with_temp_dir(&temp_dir)
}

/// Create a test configuration with a specific temporary directory
pub fn create_test_config_with_temp_dir(temp_dir: &TempDir) -> AethericConfig {
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

/// Create a test plugin configuration
pub fn create_test_plugin_config(
    name: &str,
    plugin_type: aetheric_edge::agent::plugin_manager::PluginType,
) -> aetheric_edge::agent::plugin_manager::PluginConfig {
    aetheric_edge::agent::plugin_manager::PluginConfig {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        description: Some(format!("Test plugin: {}", name)),
        plugin_type,
        auto_start: false,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        ports: Vec::new(),
        volumes: Vec::new(),
        command_args: Vec::new(),
    }
}

/// Create a test command message
pub fn create_test_command(
    id: &str,
    command: aetheric_edge::mqtt::messages::CommandType,
) -> aetheric_edge::mqtt::messages::CommandMessage {
    aetheric_edge::mqtt::messages::CommandMessage {
        id: id.to_string(),
        command,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: HashMap::new(),
    }
}

/// Assert that a command response is successful
pub fn assert_success_response(
    response: &aetheric_edge::mqtt::messages::CommandResponse,
    expected_command_id: &str,
) {
    assert_eq!(response.command_id, expected_command_id);
    assert!(matches!(
        response.status,
        aetheric_edge::mqtt::messages::CommandStatus::Success
    ));
    assert!(response.result.is_some());
}

/// Assert that a command response failed
pub fn assert_failed_response(
    response: &aetheric_edge::mqtt::messages::CommandResponse,
    expected_command_id: &str,
) {
    assert_eq!(response.command_id, expected_command_id);
    assert!(matches!(
        response.status,
        aetheric_edge::mqtt::messages::CommandStatus::Failed
    ));
}
