pub mod agent;
pub mod certs;
pub mod config;
pub mod mqtt;
pub mod setup;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn test_certificate_management() {
        let temp_dir = tempdir().unwrap();
        let cert_dir = temp_dir.path().to_path_buf();

        let cert_manager = certs::CertificateManager::new(cert_dir.clone());

        // Test certificate creation
        let result = cert_manager
            .create_device_certificate("test-device", vec!["localhost".to_string()])
            .await;
        assert!(result.is_ok(), "Certificate creation failed: {:?}", result);

        // Test certificate exists
        assert!(cert_manager.device_cert_path().exists());
        assert!(cert_manager.device_key_path().exists());

        // Test certificate info
        let cert_info = cert_manager.get_certificate_info().await.unwrap();
        assert!(cert_info.is_some());

        let info = cert_info.unwrap();
        assert!(info.subject.contains("test-device"));
        assert!(info.is_valid);

        // Test device ID extraction
        let device_id = cert_manager.extract_device_id_from_cert().unwrap();
        assert_eq!(device_id, Some("test-device".to_string()));
    }

    #[test]
    fn test_configuration_management() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test-config.toml");

        // Test default config creation
        let config = config::AethericConfig::default();
        assert_eq!(config.gateway.id, "aetheric-edge-001");
        assert_eq!(config.mqtt.host, "localhost");
        assert_eq!(config.mqtt.port, 1883);

        // Test config file operations
        let save_result = config.save_to_file(&config_path);
        assert!(save_result.is_ok(), "Config save failed: {:?}", save_result);

        let loaded_config = config::AethericConfig::load_from_file(&config_path).unwrap();
        assert_eq!(loaded_config.gateway.id, config.gateway.id);
        assert_eq!(loaded_config.mqtt.host, config.mqtt.host);

        // Test validation
        assert!(loaded_config.validate().is_ok());
    }

    #[test]
    fn test_mqtt_topics() {
        let topic_builder = mqtt::topics::TopicBuilder::new("test-device".to_string());

        assert_eq!(topic_builder.health(), "ae/test-device/health");
        assert_eq!(topic_builder.commands(), "ae/test-device/cmd/+");
        assert_eq!(
            topic_builder.command_response("cmd-123"),
            "ae/test-device/cmd/cmd-123/response"
        );

        // Test topic parsing
        let command_id =
            mqtt::topics::parse_command_topic("ae/test-device/cmd/install-001", "test-device");
        assert_eq!(command_id, Some("install-001".to_string()));

        let invalid_topic =
            mqtt::topics::parse_command_topic("ae/other-device/cmd/test", "test-device");
        assert_eq!(invalid_topic, None);
    }

    #[test]
    fn test_message_serialization() {
        // Test command message
        let command = mqtt::messages::CommandMessage {
            id: "test-001".to_string(),
            command: mqtt::messages::CommandType::Health,
            timestamp: "2025-06-18T15:00:00Z".to_string(),
            parameters: std::collections::HashMap::new(),
        };

        let json = serde_json::to_string(&command).unwrap();
        let parsed: mqtt::messages::CommandMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, command.id);

        // Test health message
        let health = mqtt::messages::HealthMessage {
            status: mqtt::messages::HealthStatus::Up,
            timestamp: "2025-06-18T15:00:00Z".to_string(),
            gateway_id: "test-device".to_string(),
            uptime_seconds: 3600,
            memory_usage_mb: 512,
            cpu_usage_percent: 25.5,
        };

        let json = serde_json::to_string(&health).unwrap();
        let parsed: mqtt::messages::HealthMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.gateway_id, health.gateway_id);
        assert_eq!(parsed.uptime_seconds, health.uptime_seconds);
    }

    #[tokio::test]
    async fn test_plugin_installation() {
        let temp_dir = tempdir().unwrap();
        let install_dir = temp_dir.path().join("plugins");
        let temp_plugin_dir = temp_dir.path().join("temp");

        fs::create_dir_all(&install_dir).await.unwrap();
        fs::create_dir_all(&temp_plugin_dir).await.unwrap();

        // Create a test binary
        let test_binary = temp_dir.path().join("test-plugin");
        fs::write(&test_binary, "#!/bin/bash\necho 'Hello World'\n")
            .await
            .unwrap();

        // Test config with custom directories
        let mut config = config::AethericConfig::default();
        config.plugins.install_dir = install_dir.clone();
        config.plugins.temp_dir = temp_plugin_dir;

        // Test that configuration is valid
        assert!(config.validate().is_ok());

        // Verify plugin directory structure
        let plugin_path = config.plugins.install_dir.join("test-plugin");
        assert!(!plugin_path.exists()); // Should not exist initially
    }

    #[tokio::test]
    async fn test_setup_configuration() {
        let _temp_dir = tempdir().unwrap();

        // Test setup configuration creation
        let setup_config = setup::SetupConfig::default();

        // Verify default values
        assert!(!setup_config.gateway_id.is_empty());
        assert!(setup_config.gateway_id.starts_with("aetheric-"));
        assert_eq!(setup_config.mqtt_remote_host, "your-cloud-mqtt-broker.com");
        assert_eq!(setup_config.mqtt_remote_port, 8883);
        assert_eq!(setup_config.mqtt_local_username, "aetheric");
        assert!(!setup_config.mqtt_local_password.is_empty());
        assert_eq!(setup_config.health_report_interval, 60);
        assert!(setup_config.ssh_enabled);
        assert_eq!(setup_config.ssh_port, 22);
        assert!(setup_config.plugins_docker_enabled);

        // Test setup options
        let options = setup::SetupOptions {
            interactive: false,
            auto: true,
            force: false,
            skip_services: true,
        };

        assert!(!options.interactive);
        assert!(options.auto);
        assert!(!options.force);
        assert!(options.skip_services);
    }
}
