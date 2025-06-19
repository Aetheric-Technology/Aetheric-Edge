use anyhow::Result;
use rumqttc::{MqttOptions, QoS};
use serde_json::Value;
use std::collections::HashMap;
use tokio::time::Duration;

/// Tests for MQTT error handling and edge cases

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

fn validate_topic(topic: &str) -> Result<()> {
    if topic.is_empty() {
        return Err(anyhow::anyhow!("Topic cannot be empty"));
    }

    // Check for invalid characters (basic validation)
    if topic.contains('\0') {
        return Err(anyhow::anyhow!("Topic cannot contain null characters"));
    }

    Ok(())
}

fn validate_message_size(message: &[u8], max_size: usize) -> Result<()> {
    if message.len() > max_size {
        return Err(anyhow::anyhow!(
            "Message size {} exceeds maximum allowed size {}",
            message.len(),
            max_size
        ));
    }
    Ok(())
}

fn validate_json_message(message: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(message) {
        Ok(value) => Ok(value),
        Err(e) => Err(anyhow::anyhow!("Invalid JSON: {}", e)),
    }
}

fn create_mqtt_options_with_validation(
    host: &str,
    port: u16,
    client_id: &str,
) -> Result<MqttOptions> {
    if host.is_empty() {
        return Err(anyhow::anyhow!("Host cannot be empty"));
    }

    if port == 0 {
        return Err(anyhow::anyhow!("Port cannot be zero"));
    }

    if client_id.is_empty() {
        return Err(anyhow::anyhow!("Client ID cannot be empty"));
    }

    let mut options = MqttOptions::new(client_id, host, port);
    options.set_keep_alive(Duration::from_secs(30));

    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_boundary_values() {
        // Test boundary values
        assert!(validate_qos(0).is_ok());
        assert!(validate_qos(1).is_ok());
        assert!(validate_qos(2).is_ok());
        assert!(validate_qos(3).is_err());
        assert!(validate_qos(255).is_err());
    }

    #[test]
    fn test_topic_validation_empty() {
        assert!(validate_topic("").is_err());
        let error = validate_topic("").unwrap_err();
        assert!(error.to_string().contains("Topic cannot be empty"));
    }

    #[test]
    fn test_topic_validation_null_characters() {
        let topic_with_null = "topic\0with\0null";
        assert!(validate_topic(topic_with_null).is_err());
        let error = validate_topic(topic_with_null).unwrap_err();
        assert!(error.to_string().contains("null characters"));
    }

    #[test]
    fn test_topic_validation_valid_topics() {
        let valid_topics = vec![
            "simple",
            "path/to/topic",
            "device/sensor-001/temperature",
            "+/wildcard",
            "multi/+/wildcards/+",
            "#",
            "topic/with/+/and/#",
            "very/long/topic/path/with/many/segments/that/should/still/be/valid",
        ];

        for topic in valid_topics {
            assert!(
                validate_topic(topic).is_ok(),
                "Topic should be valid: {}",
                topic
            );
        }
    }

    #[test]
    fn test_message_size_validation() {
        let max_size = 1024;

        // Valid sizes
        assert!(validate_message_size(b"small", max_size).is_ok());
        assert!(validate_message_size(&vec![0u8; max_size], max_size).is_ok());

        // Invalid size
        assert!(validate_message_size(&vec![0u8; max_size + 1], max_size).is_err());

        let error = validate_message_size(&vec![0u8; max_size + 1], max_size).unwrap_err();
        assert!(error.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_json_validation_valid() {
        let valid_json_examples = vec![
            r#"{"key": "value"}"#,
            r#"{"number": 42}"#,
            r#"{"boolean": true}"#,
            r#"{"null": null}"#,
            r#"{"array": [1, 2, 3]}"#,
            r#"{"nested": {"object": "value"}}"#,
            r#"[]"#,
            r#"{}"#,
            r#""string""#,
            r#"42"#,
            r#"true"#,
            r#"null"#,
        ];

        for json in valid_json_examples {
            assert!(
                validate_json_message(json).is_ok(),
                "Should be valid JSON: {}",
                json
            );
        }
    }

    #[test]
    fn test_json_validation_invalid() {
        let invalid_json_examples = vec![
            r#"{"key": value}"#,        // Unquoted value
            r#"{"key": "value",}"#,     // Trailing comma
            r#"{key: "value"}"#,        // Unquoted key
            r#"{"incomplete":"#,        // Incomplete
            r#"{"number": 42.}"#,       // Invalid number
            r#"{"boolean": True}"#,     // Wrong boolean
            r#"{"null": Null}"#,        // Wrong null
            r#"{"array": [1, 2, 3,]}"#, // Trailing comma in array
            r#"not json at all"#,
            r#""unclosed string"#,
            r#"{"double": "quotes": "error"}"#,
        ];

        for json in invalid_json_examples {
            assert!(
                validate_json_message(json).is_err(),
                "Should be invalid JSON: {}",
                json
            );
        }
    }

    #[test]
    fn test_mqtt_options_validation_empty_host() {
        let result = create_mqtt_options_with_validation("", 1883, "client");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Host cannot be empty"));
    }

    #[test]
    fn test_mqtt_options_validation_zero_port() {
        let result = create_mqtt_options_with_validation("localhost", 0, "client");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Port cannot be zero"));
    }

    #[test]
    fn test_mqtt_options_validation_empty_client_id() {
        let result = create_mqtt_options_with_validation("localhost", 1883, "");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Client ID cannot be empty"));
    }

    #[test]
    fn test_mqtt_options_validation_valid() {
        let result = create_mqtt_options_with_validation("localhost", 1883, "test-client");
        assert!(result.is_ok());

        let options = result.unwrap();
        let (host, port) = options.broker_address();
        assert_eq!(host, "localhost");
        assert_eq!(port, 1883);
        assert_eq!(options.keep_alive(), Duration::from_secs(30));
    }

    #[test]
    fn test_extreme_message_sizes() {
        // Test various message sizes
        let test_cases = vec![
            (0, 1024, true),      // Empty message
            (1, 1024, true),      // 1 byte
            (1024, 1024, true),   // Exactly at limit
            (1025, 1024, false),  // Just over limit
            (10240, 1024, false), // Way over limit
        ];

        for (size, limit, should_pass) in test_cases {
            let message = vec![b'A'; size];
            let result = validate_message_size(&message, limit);

            if should_pass {
                assert!(
                    result.is_ok(),
                    "Size {} should pass with limit {}",
                    size,
                    limit
                );
            } else {
                assert!(
                    result.is_err(),
                    "Size {} should fail with limit {}",
                    size,
                    limit
                );
            }
        }
    }

    #[test]
    fn test_unicode_in_topics_and_messages() {
        // Test Unicode characters in topics
        let unicode_topics = vec![
            "sensor/温度",
            "device/sensor-001/température",
            "测试/topic",
            "topic/with/émojis/🌡️",
        ];

        for topic in unicode_topics {
            // Unicode should be allowed in topics
            assert!(
                validate_topic(topic).is_ok(),
                "Unicode topic should be valid: {}",
                topic
            );
        }

        // Test Unicode in JSON messages
        let unicode_json = r#"{"message": "Hello 世界", "emoji": "🚀", "temp": "23°C"}"#;
        assert!(validate_json_message(unicode_json).is_ok());
    }

    #[test]
    fn test_very_long_topics() {
        // Test extremely long topics
        let normal_topic = "a".repeat(100);
        assert!(validate_topic(&normal_topic).is_ok());

        let long_topic = "a".repeat(1000);
        assert!(validate_topic(&long_topic).is_ok());

        let very_long_topic = "a".repeat(10000);
        assert!(validate_topic(&very_long_topic).is_ok());
    }

    #[test]
    fn test_special_characters_in_topics() {
        let special_topics = vec![
            "topic/with spaces",
            "topic-with-dashes",
            "topic_with_underscores",
            "topic.with.dots",
            "topic:with:colons",
            "topic(with)parentheses",
            "topic[with]brackets",
            "topic{with}braces",
        ];

        for topic in special_topics {
            // Most special characters should be allowed
            assert!(
                validate_topic(topic).is_ok(),
                "Topic with special chars should be valid: {}",
                topic
            );
        }
    }

    #[test]
    fn test_json_edge_cases() {
        // Test deeply nested JSON
        let deep_json = r#"{"level1": {"level2": {"level3": {"level4": {"level5": "deep"}}}}}"#;
        assert!(validate_json_message(deep_json).is_ok());

        // Test JSON with many fields
        let mut large_object = HashMap::new();
        for i in 0..1000 {
            large_object.insert(format!("field_{}", i), i);
        }
        let large_json = serde_json::to_string(&large_object).unwrap();
        assert!(validate_json_message(&large_json).is_ok());

        // Test JSON with escaped characters
        let escaped_json = r#"{"escaped": "\"quoted string\" with \n newlines and \t tabs"}"#;
        assert!(validate_json_message(escaped_json).is_ok());
    }

    #[test]
    fn test_port_boundary_values() {
        // Test port boundary values
        let test_cases = vec![
            (1, true),     // Minimum valid port
            (80, true),    // Common HTTP port
            (443, true),   // Common HTTPS port
            (1883, true),  // Standard MQTT port
            (8883, true),  // Standard MQTT over TLS port
            (65535, true), // Maximum valid port
        ];

        for (port, should_pass) in test_cases {
            let result = create_mqtt_options_with_validation("localhost", port, "client");
            if should_pass {
                assert!(result.is_ok(), "Port {} should be valid", port);
            } else {
                assert!(result.is_err(), "Port {} should be invalid", port);
            }
        }
    }

    #[test]
    fn test_host_validation_edge_cases() {
        let test_cases = vec![
            ("localhost", true),
            ("127.0.0.1", true),
            ("::1", true),
            ("broker.hivemq.com", true),
            ("test.mosquitto.org", true),
            ("192.168.1.100", true),
            ("mqtt-broker-with-very-long-hostname.example.com", true),
            ("", false), // Empty host
        ];

        for (host, should_pass) in test_cases {
            let result = create_mqtt_options_with_validation(host, 1883, "client");
            if should_pass {
                assert!(result.is_ok(), "Host '{}' should be valid", host);
            } else {
                assert!(result.is_err(), "Host '{}' should be invalid", host);
            }
        }
    }

    #[test]
    fn test_client_id_edge_cases() {
        let test_cases = vec![
            ("simple", true),
            ("client-with-dashes", true),
            ("client_with_underscores", true),
            ("client123", true),
            ("very-long-client-id-that-should-still-be-acceptable", true),
            ("client.with.dots", true),
            ("", false), // Empty client ID
        ];

        for (client_id, should_pass) in test_cases {
            let result = create_mqtt_options_with_validation("localhost", 1883, client_id);
            if should_pass {
                assert!(result.is_ok(), "Client ID '{}' should be valid", client_id);
            } else {
                assert!(
                    result.is_err(),
                    "Client ID '{}' should be invalid",
                    client_id
                );
            }
        }
    }

    #[test]
    fn test_concurrent_validation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let success_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..100)
            .map(|i| {
                let success_count = success_count.clone();
                let error_count = error_count.clone();

                thread::spawn(move || {
                    // Test with valid and invalid QoS values
                    let qos = if i % 4 == 3 { 5 } else { i % 3 }; // 25% invalid

                    match validate_qos(qos as u8) {
                        Ok(_) => success_count.fetch_add(1, Ordering::Relaxed),
                        Err(_) => error_count.fetch_add(1, Ordering::Relaxed),
                    };
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let total_success = success_count.load(Ordering::Relaxed);
        let total_errors = error_count.load(Ordering::Relaxed);

        assert_eq!(total_success + total_errors, 100);
        assert_eq!(total_success, 75); // 75% should be valid (QoS 0, 1, 2)
        assert_eq!(total_errors, 25); // 25% should be invalid (QoS 5)
    }
}
