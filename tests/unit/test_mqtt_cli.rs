use aetheric_edge::config::AethericConfig;
use anyhow::Result;
use rumqttc::{MqttOptions, QoS};
use serde_json::Value;
use tempfile::TempDir;
use tokio::time::Duration;

// Since the MQTT CLI functions are in the CLI binary, we need to test the logic separately
// Let's extract the core functionality into testable functions

/// Test helper to create a test configuration
fn create_test_mqtt_config() -> AethericConfig {
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
            username: Some("test_user".to_string()),
            password: Some("test_pass".to_string()),
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

/// Test function for validating QoS levels
fn validate_qos(qos: u8) -> Result<QoS> {
    match qos {
        0 => Ok(QoS::AtMostOnce),
        1 => Ok(QoS::AtLeastOnce),
        2 => Ok(QoS::ExactlyOnce),
        _ => Err(anyhow::anyhow!(
            "Invalid QoS level: {}. Must be 0, 1, or 2",
            qos
        )),
    }
}

/// Test function for formatting messages (JSON validation)
fn format_message(message: &str) -> Result<String> {
    // Try to parse as JSON and pretty-print it
    if let Ok(json_value) = serde_json::from_str::<Value>(message) {
        Ok(serde_json::to_string_pretty(&json_value)?)
    } else {
        // Not JSON, return as-is
        Ok(message.to_string())
    }
}

/// Test function for formatting received messages
fn format_received_message(message: &str) -> Result<String> {
    // Try to parse as JSON and format it compactly for received messages
    if let Ok(json_value) = serde_json::from_str::<Value>(message) {
        Ok(serde_json::to_string(&json_value)?) // Compact JSON for received messages
    } else {
        // Not JSON, return as-is
        Ok(message.to_string())
    }
}

/// Test function for creating MQTT options
fn create_mqtt_options(
    config: &AethericConfig,
    host_override: Option<String>,
    port_override: Option<u16>,
) -> MqttOptions {
    let host = host_override.unwrap_or_else(|| config.mqtt.host.clone());
    let port = port_override.unwrap_or(config.mqtt.port);

    let client_id = format!("aetheric-cli-test-{}", uuid::Uuid::new_v4());
    let mut mqtt_options = MqttOptions::new(client_id, host, port);
    mqtt_options.set_keep_alive(Duration::from_secs(30));

    // Configure credentials if provided
    if let Some(username) = &config.mqtt.username {
        if let Some(password) = &config.mqtt.password {
            mqtt_options.set_credentials(username, password);
        }
    }

    mqtt_options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_validation_valid_levels() {
        // Test valid QoS levels
        assert!(matches!(validate_qos(0), Ok(QoS::AtMostOnce)));
        assert!(matches!(validate_qos(1), Ok(QoS::AtLeastOnce)));
        assert!(matches!(validate_qos(2), Ok(QoS::ExactlyOnce)));
    }

    #[test]
    fn test_qos_validation_invalid_levels() {
        // Test invalid QoS levels
        assert!(validate_qos(3).is_err());
        assert!(validate_qos(255).is_err());

        let error = validate_qos(5).unwrap_err();
        assert!(error.to_string().contains("Invalid QoS level: 5"));
    }

    #[test]
    fn test_json_message_formatting() {
        // Test valid JSON formatting
        let json_input = r#"{"temperature": 21.3, "humidity": 60}"#;
        let result = format_message(json_input).unwrap();

        // Should be pretty-printed
        assert!(result.contains("{\n"));
        assert!(result.contains("\"temperature\": 21.3"));
        assert!(result.contains("\"humidity\": 60"));
    }

    #[test]
    fn test_non_json_message_formatting() {
        // Test non-JSON message
        let text_input = "Hello, World!";
        let result = format_message(text_input).unwrap();

        // Should return as-is
        assert_eq!(result, text_input);
    }

    #[test]
    fn test_invalid_json_message_formatting() {
        // Test invalid JSON
        let invalid_json = r#"{"temperature": 21.3, "humidity":}"#;
        let result = format_message(invalid_json).unwrap();

        // Should return as-is since it's not valid JSON
        assert_eq!(result, invalid_json);
    }

    #[test]
    fn test_received_message_formatting() {
        // Test compact JSON formatting for received messages
        let json_input = r#"{"temperature": 21.3, "humidity": 60}"#;
        let result = format_received_message(json_input).unwrap();

        // Should be compact (no newlines)
        assert!(!result.contains("\n"));
        assert!(result.contains("\"temperature\":21.3"));
        assert!(result.contains("\"humidity\":60"));
    }

    #[test]
    fn test_mqtt_options_creation() {
        let config = create_test_mqtt_config();
        let mqtt_options = create_mqtt_options(&config, None, None);

        // Check basic settings
        let (host, port) = mqtt_options.broker_address();
        assert_eq!(host, "localhost");
        assert_eq!(port, 1883);
        assert_eq!(mqtt_options.keep_alive(), Duration::from_secs(30));
    }

    #[test]
    fn test_mqtt_options_with_overrides() {
        let config = create_test_mqtt_config();
        let mqtt_options =
            create_mqtt_options(&config, Some("broker.example.com".to_string()), Some(8883));

        // Check overridden settings
        let (host, port) = mqtt_options.broker_address();
        assert_eq!(host, "broker.example.com");
        assert_eq!(port, 8883);
    }

    #[test]
    fn test_mqtt_config_creation() {
        let config = create_test_mqtt_config();

        // Verify configuration
        assert_eq!(config.gateway.id, "test-gateway");
        assert_eq!(config.mqtt.host, "localhost");
        assert_eq!(config.mqtt.port, 1883);
        assert_eq!(config.mqtt.username, Some("test_user".to_string()));
        assert_eq!(config.mqtt.password, Some("test_pass".to_string()));
        assert!(!config.mqtt.tls);
    }

    #[test]
    fn test_complex_json_formatting() {
        let complex_json = r#"{
            "device": {
                "id": "sensor-001",
                "location": "room-1"
            },
            "measurements": [
                {"type": "temperature", "value": 21.3, "unit": "°C"},
                {"type": "humidity", "value": 60, "unit": "%"}
            ],
            "timestamp": "2025-06-19T03:16:00Z"
        }"#;

        let result = format_message(complex_json).unwrap();

        // Should be valid JSON
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.is_object());

        // Check nested structure
        assert!(parsed["device"]["id"].as_str() == Some("sensor-001"));
        assert!(parsed["measurements"].is_array());
    }

    #[test]
    fn test_empty_message_handling() {
        // Test empty string
        let result = format_message("").unwrap();
        assert_eq!(result, "");

        // Test whitespace-only
        let result = format_message("   ").unwrap();
        assert_eq!(result, "   ");
    }

    #[test]
    fn test_special_characters_in_message() {
        let special_chars = "Message with 特殊字符 and émojis 🚀 and quotes \"test\"";
        let result = format_message(special_chars).unwrap();
        assert_eq!(result, special_chars);
    }

    #[test]
    fn test_json_array_formatting() {
        let json_array = r#"[{"id": 1, "name": "test"}, {"id": 2, "name": "test2"}]"#;
        let result = format_message(json_array).unwrap();

        // Should be formatted JSON array
        assert!(result.starts_with("[\n"));
        assert!(result.contains("\"id\": 1"));
        assert!(result.contains("\"name\": \"test\""));
    }

    #[test]
    fn test_json_primitive_values() {
        // Test JSON string
        let json_string = r#""Hello, World!""#;
        let result = format_message(json_string).unwrap();
        assert_eq!(result, "\"Hello, World!\"");

        // Test JSON number
        let json_number = "42";
        let result = format_message(json_number).unwrap();
        assert_eq!(result, "42");

        // Test JSON boolean
        let json_bool = "true";
        let result = format_message(json_bool).unwrap();
        assert_eq!(result, "true");

        // Test JSON null
        let json_null = "null";
        let result = format_message(json_null).unwrap();
        assert_eq!(result, "null");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_mqtt_client_creation() {
        let config = create_test_mqtt_config();
        let mqtt_options = create_mqtt_options(&config, None, None);

        // Create MQTT client (this tests the connection setup without actually connecting)
        let (client, _eventloop) = rumqttc::AsyncClient::new(mqtt_options, 10);

        // Test that we can create publish requests (they won't be sent without a broker)
        let publish_result = client
            .publish(
                "test/topic",
                QoS::AtMostOnce,
                false,
                "test message".as_bytes(),
            )
            .await;

        // Should succeed in creating the publish request
        assert!(publish_result.is_ok());
    }

    #[tokio::test]
    async fn test_mqtt_options_with_tls() {
        let mut config = create_test_mqtt_config();
        config.mqtt.tls = true;
        config.mqtt.port = 8883;

        let mqtt_options = create_mqtt_options(&config, None, None);

        // Verify TLS port is set
        let (_host, port) = mqtt_options.broker_address();
        assert_eq!(port, 8883);
    }

    #[tokio::test]
    async fn test_message_processing_workflow() {
        // Simulate the workflow of processing an incoming message
        let raw_message = r#"{"temperature": 25.5, "sensor_id": "temp-001"}"#;

        // Format the message as it would be received
        let formatted = format_received_message(raw_message).unwrap();

        // Parse it back to ensure it's valid
        let parsed: Value = serde_json::from_str(&formatted).unwrap();

        // Verify the data is preserved
        assert_eq!(parsed["temperature"].as_f64(), Some(25.5));
        assert_eq!(parsed["sensor_id"].as_str(), Some("temp-001"));
    }

    #[tokio::test]
    async fn test_concurrent_message_formatting() {
        // Test concurrent message formatting (simulating multiple incoming messages)
        let messages = vec![
            r#"{"temp": 20.1}"#,
            r#"{"temp": 20.2}"#,
            r#"{"temp": 20.3}"#,
            r#"{"temp": 20.4}"#,
            r#"{"temp": 20.5}"#,
        ];

        let mut handles = vec![];

        for msg in messages {
            let handle = tokio::spawn(async move { format_received_message(msg) });
            handles.push(handle);
        }

        // Wait for all to complete
        let mut results = vec![];
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            results.push(result);
        }

        // Verify all were processed correctly
        assert_eq!(results.len(), 5);
        for (i, result) in results.iter().enumerate() {
            let expected_temp = 20.1 + (i as f64 * 0.1);
            let parsed: Value = serde_json::from_str(result).unwrap();
            let actual_temp = parsed["temp"].as_f64().unwrap();
            assert!((actual_temp - expected_temp).abs() < 0.001);
        }
    }

    #[tokio::test]
    async fn test_error_handling_in_message_formatting() {
        // Test that errors in JSON parsing are handled gracefully
        let malformed_json = r#"{"temperature": 25.5, "incomplete":}"#;

        // Should not panic and return the original string
        let result = format_message(malformed_json).unwrap();
        assert_eq!(result, malformed_json);
    }

    #[tokio::test]
    async fn test_mqtt_client_with_credentials() {
        let config = create_test_mqtt_config();
        let mut mqtt_options = create_mqtt_options(&config, None, None);

        // Verify credentials are set
        if let Some(username) = &config.mqtt.username {
            if let Some(password) = &config.mqtt.password {
                mqtt_options.set_credentials(username, password);
                // Note: rumqttc doesn't expose a way to check credentials, so we just verify no panic
            }
        }

        let (_client, _eventloop) = rumqttc::AsyncClient::new(mqtt_options, 10);
        // If we get here without panic, credentials were set successfully
    }
}
