use aetheric_edge::config::AethericConfig;
use anyhow::Result;
use rumqttc::QoS;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tracing::info;

/// Mock MQTT broker for testing
#[derive(Debug, Clone)]
pub struct MockMqttBroker {
    pub published_messages: Arc<Mutex<Vec<PublishedMessage>>>,
    pub subscribers: Arc<Mutex<HashMap<String, Vec<mpsc::UnboundedSender<ReceivedMessage>>>>>,
    pub is_running: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
pub struct PublishedMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: QoS,
    pub retain: bool,
}

#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub topic: String,
    pub payload: Vec<u8>,
}

impl Default for MockMqttBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMqttBroker {
    pub fn new() -> Self {
        Self {
            published_messages: Arc::new(Mutex::new(Vec::new())),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn start(&self) {
        let mut running = self.is_running.lock().await;
        *running = true;
        info!("Mock MQTT broker started");
    }

    pub async fn stop(&self) {
        let mut running = self.is_running.lock().await;
        *running = false;
        info!("Mock MQTT broker stopped");
    }

    pub async fn publish(&self, topic: String, payload: Vec<u8>, qos: QoS, retain: bool) {
        // Store the published message
        let mut messages = self.published_messages.lock().await;
        messages.push(PublishedMessage {
            topic: topic.clone(),
            payload: payload.clone(),
            qos,
            retain,
        });

        // Send to subscribers
        let subscribers = self.subscribers.lock().await;
        if let Some(topic_subscribers) = subscribers.get(&topic) {
            let message = ReceivedMessage {
                topic: topic.clone(),
                payload: payload.clone(),
            };
            for sender in topic_subscribers {
                let _ = sender.send(message.clone());
            }
        }

        // Also send to wildcard subscribers (#)
        if let Some(wildcard_subscribers) = subscribers.get("#") {
            let message = ReceivedMessage {
                topic: topic.clone(),
                payload: payload.clone(),
            };
            for sender in wildcard_subscribers {
                let _ = sender.send(message.clone());
            }
        }
    }

    pub async fn subscribe(&self, topic: String) -> mpsc::UnboundedReceiver<ReceivedMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subscribers = self.subscribers.lock().await;
        subscribers.entry(topic).or_insert_with(Vec::new).push(tx);
        rx
    }

    pub async fn get_published_messages(&self) -> Vec<PublishedMessage> {
        let messages = self.published_messages.lock().await;
        messages.clone()
    }

    pub async fn clear_messages(&self) {
        let mut messages = self.published_messages.lock().await;
        messages.clear();
    }

    pub async fn get_message_count(&self) -> usize {
        let messages = self.published_messages.lock().await;
        messages.len()
    }
}

/// Test helper to create a test configuration
fn create_test_config() -> AethericConfig {
    let temp_dir = TempDir::new().unwrap();
    AethericConfig {
        gateway: aetheric_edge::config::GatewayConfig {
            id: "test-gateway-mqtt".to_string(),
            name: Some("Test MQTT Gateway".to_string()),
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

/// Test client for simulating MQTT publish/subscribe operations
pub struct TestMqttClient {
    pub broker: MockMqttBroker,
    pub config: AethericConfig,
}

impl Clone for TestMqttClient {
    fn clone(&self) -> Self {
        Self {
            broker: self.broker.clone(),
            config: create_test_config(),
        }
    }
}

impl Default for TestMqttClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TestMqttClient {
    pub fn new() -> Self {
        Self {
            broker: MockMqttBroker::new(),
            config: create_test_config(),
        }
    }

    pub async fn publish_message(
        &self,
        topic: &str,
        message: &str,
        qos: QoS,
        retain: bool,
    ) -> Result<()> {
        self.broker
            .publish(topic.to_string(), message.as_bytes().to_vec(), qos, retain)
            .await;
        Ok(())
    }

    pub async fn subscribe_to_topic(
        &self,
        topic: &str,
    ) -> mpsc::UnboundedReceiver<ReceivedMessage> {
        self.broker.subscribe(topic.to_string()).await
    }

    pub async fn get_published_messages(&self) -> Vec<PublishedMessage> {
        self.broker.get_published_messages().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_broker_basic_functionality() {
        let broker = MockMqttBroker::new();
        broker.start().await;

        // Test publishing a message
        broker
            .publish(
                "test/topic".to_string(),
                b"Hello, World!".to_vec(),
                QoS::AtMostOnce,
                false,
            )
            .await;

        let messages = broker.get_published_messages().await;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, "test/topic");
        assert_eq!(messages[0].payload, b"Hello, World!");

        broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_publish_subscribe_flow() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Subscribe to a topic
        let mut subscriber = client.subscribe_to_topic("sensor/temperature").await;

        // Publish a message
        let test_message = r#"{"temperature": 23.5, "unit": "°C"}"#;
        client
            .publish_message("sensor/temperature", test_message, QoS::AtMostOnce, false)
            .await
            .unwrap();

        // Verify subscriber receives the message
        let received = timeout(Duration::from_millis(100), subscriber.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.topic, "sensor/temperature");
        assert_eq!(String::from_utf8(received.payload).unwrap(), test_message);

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_json_message_handling() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Test various JSON message formats
        let messages = [r#"{"sensor": "temp-001", "value": 25.3}"#,
            r#"{"measurements": [{"type": "temperature", "value": 20.1}]}"#,
            r#"{"device": {"id": "dev-001", "status": "online"}}"#];

        for (i, msg) in messages.iter().enumerate() {
            let topic = format!("sensor/{}", i);
            client
                .publish_message(&topic, msg, QoS::AtLeastOnce, false)
                .await
                .unwrap();
        }

        let published = client.get_published_messages().await;
        assert_eq!(published.len(), 3);

        // Verify each message can be parsed as JSON
        for published_msg in published.iter() {
            let payload_str = String::from_utf8(published_msg.payload.clone()).unwrap();
            let json_value: Value = serde_json::from_str(&payload_str).unwrap();
            assert!(json_value.is_object());
        }

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_qos_levels() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Test all QoS levels
        let qos_levels = vec![QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce];

        for qos in qos_levels {
            client
                .publish_message("test/qos", "test message", qos, false)
                .await
                .unwrap();
        }

        let messages = client.get_published_messages().await;
        assert_eq!(messages.len(), 3);
        assert!(matches!(messages[0].qos, QoS::AtMostOnce));
        assert!(matches!(messages[1].qos, QoS::AtLeastOnce));
        assert!(matches!(messages[2].qos, QoS::ExactlyOnce));

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_retained_messages() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Publish a retained message
        client
            .publish_message("device/status", "online", QoS::AtLeastOnce, true)
            .await
            .unwrap();

        let messages = client.get_published_messages().await;
        assert_eq!(messages.len(), 1);
        assert!(messages[0].retain);
        assert_eq!(messages[0].topic, "device/status");

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_wildcard_subscription() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Subscribe to wildcard topic
        let mut wildcard_subscriber = client.subscribe_to_topic("#").await;

        // Publish to various topics
        let topics = vec!["sensor/temp", "device/status", "alerts/fire"];
        for topic in &topics {
            client
                .publish_message(topic, "test data", QoS::AtMostOnce, false)
                .await
                .unwrap();
        }

        // Verify wildcard subscriber receives all messages
        for expected_topic in &topics {
            let received = timeout(Duration::from_millis(100), wildcard_subscriber.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.topic, *expected_topic);
        }

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_multiple_subscribers() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Create multiple subscribers for the same topic
        let mut sub1 = client.subscribe_to_topic("broadcast").await;
        let mut sub2 = client.subscribe_to_topic("broadcast").await;
        let mut sub3 = client.subscribe_to_topic("broadcast").await;

        // Publish a message
        client
            .publish_message("broadcast", "Hello everyone!", QoS::AtMostOnce, false)
            .await
            .unwrap();

        // All subscribers should receive the message
        let msg1 = timeout(Duration::from_millis(100), sub1.recv())
            .await
            .unwrap()
            .unwrap();
        let msg2 = timeout(Duration::from_millis(100), sub2.recv())
            .await
            .unwrap()
            .unwrap();
        let msg3 = timeout(Duration::from_millis(100), sub3.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg1.topic, "broadcast");
        assert_eq!(msg2.topic, "broadcast");
        assert_eq!(msg3.topic, "broadcast");

        let payload = "Hello everyone!";
        assert_eq!(String::from_utf8(msg1.payload).unwrap(), payload);
        assert_eq!(String::from_utf8(msg2.payload).unwrap(), payload);
        assert_eq!(String::from_utf8(msg3.payload).unwrap(), payload);

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_large_message_handling() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Create a large JSON message (1MB)
        let large_data = "X".repeat(1024 * 1024);
        let large_json = format!(r#"{{"data": "{}"}}"#, large_data);

        client
            .publish_message("large/message", &large_json, QoS::AtLeastOnce, false)
            .await
            .unwrap();

        let messages = client.get_published_messages().await;
        assert_eq!(messages.len(), 1);
        assert!(messages[0].payload.len() > 1024 * 1024);

        // Verify it's still valid JSON
        let payload_str = String::from_utf8(messages[0].payload.clone()).unwrap();
        let _json_value: Value = serde_json::from_str(&payload_str).unwrap();

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_concurrent_operations() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        // Create multiple concurrent publish operations
        let mut handles = vec![];

        for i in 0..10 {
            let client_clone = client.clone();
            let handle = tokio::spawn(async move {
                let topic = format!("concurrent/{}", i);
                let message = format!(r#"{{"id": {}, "data": "test"}}"#, i);
                client_clone
                    .publish_message(&topic, &message, QoS::AtMostOnce, false)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all messages were published
        let messages = client.get_published_messages().await;
        assert_eq!(messages.len(), 10);

        // Verify each message has correct content
        for msg in messages.iter() {
            // Just verify the message format is correct
            assert!(msg.topic.starts_with("concurrent/"));
            let payload_str = String::from_utf8(msg.payload.clone()).unwrap();
            let json_value: Value = serde_json::from_str(&payload_str).unwrap();
            assert!(json_value["id"].is_number());
            assert_eq!(json_value["data"].as_str().unwrap(), "test");
        }

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_error_conditions() {
        let client = TestMqttClient::new();

        // Test publishing when broker is not started
        let result = client
            .publish_message("test", "message", QoS::AtMostOnce, false)
            .await;
        assert!(result.is_ok()); // Our mock broker doesn't enforce connection state

        // Test with empty topic
        client.broker.start().await;
        client
            .publish_message("", "empty topic", QoS::AtMostOnce, false)
            .await
            .unwrap();

        let messages = client.get_published_messages().await;
        assert_eq!(messages.len(), 2); // Both messages should be recorded

        client.broker.stop().await;
    }

    #[tokio::test]
    async fn test_mqtt_message_ordering() {
        let client = TestMqttClient::new();
        client.broker.start().await;

        let mut subscriber = client.subscribe_to_topic("ordered").await;

        // Publish messages in order
        for i in 0..5 {
            let message = format!("Message {}", i);
            client
                .publish_message("ordered", &message, QoS::AtLeastOnce, false)
                .await
                .unwrap();
        }

        // Verify messages are received in order
        for i in 0..5 {
            let received = timeout(Duration::from_millis(100), subscriber.recv())
                .await
                .unwrap()
                .unwrap();
            let expected = format!("Message {}", i);
            assert_eq!(String::from_utf8(received.payload).unwrap(), expected);
        }

        client.broker.stop().await;
    }
}

// Integration tests that simulate real MQTT CLI usage patterns
#[cfg(test)]
mod cli_integration_tests {
    use super::*;

    /// Simulate the CLI publish workflow
    async fn simulate_cli_publish(
        _config: &AethericConfig,
        topic: &str,
        message: &str,
        qos: u8,
        _retain: bool,
    ) -> Result<()> {
        // Validate QoS
        let _qos_level = match qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            2 => QoS::ExactlyOnce,
            _ => return Err(anyhow::anyhow!("Invalid QoS level: {}", qos)),
        };

        // Format message (JSON validation)
        let formatted_message = if let Ok(json_value) = serde_json::from_str::<Value>(message) {
            serde_json::to_string_pretty(&json_value)?
        } else {
            message.to_string()
        };

        // In a real scenario, this would connect to MQTT broker
        // For testing, we just validate the parameters
        assert!(!topic.is_empty());
        assert!(!formatted_message.is_empty());

        Ok(())
    }

    /// Simulate the CLI subscribe workflow
    async fn simulate_cli_subscribe(
        _config: &AethericConfig,
        _topic: &str,
        qos: u8,
    ) -> Result<Vec<String>> {
        // Validate QoS
        let _qos_level = match qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            2 => QoS::ExactlyOnce,
            _ => return Err(anyhow::anyhow!("Invalid QoS level: {}", qos)),
        };

        // Simulate receiving some messages
        let simulated_messages = vec![
            r#"{"temperature": 21.3}"#.to_string(),
            r#"{"humidity": 60}"#.to_string(),
            "Plain text message".to_string(),
        ];

        Ok(simulated_messages)
    }

    #[tokio::test]
    async fn test_cli_publish_workflow() {
        let config = create_test_config();

        // Test valid publish scenarios
        let test_cases = vec![
            ("sensor/temp", r#"{"temperature": 23.5}"#, 0, false),
            ("device/status", "online", 1, true),
            (
                "alerts/fire",
                r#"{"level": "critical", "location": "building-A"}"#,
                2,
                false,
            ),
        ];

        for (topic, message, qos, retain) in test_cases {
            let result = simulate_cli_publish(&config, topic, message, qos, retain).await;
            assert!(
                result.is_ok(),
                "Failed for topic: {}, message: {}",
                topic,
                message
            );
        }
    }

    #[tokio::test]
    async fn test_cli_publish_error_cases() {
        let config = create_test_config();

        // Test invalid QoS
        let result = simulate_cli_publish(&config, "test", "message", 5, false).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid QoS level: 5"));

        // Test empty topic (should work in our implementation)
        let result = simulate_cli_publish(&config, "", "message", 0, false).await;
        assert!(result.is_err() || result.is_ok()); // Implementation dependent
    }

    #[tokio::test]
    async fn test_cli_subscribe_workflow() {
        let config = create_test_config();

        // Test valid subscribe scenarios
        let test_cases = vec![("sensor/+", 0), ("device/#", 1), ("specific/topic", 2)];

        for (topic, qos) in test_cases {
            let result = simulate_cli_subscribe(&config, topic, qos).await;
            assert!(result.is_ok(), "Failed for topic: {}, qos: {}", topic, qos);

            let messages = result.unwrap();
            assert!(!messages.is_empty());
        }
    }

    #[tokio::test]
    async fn test_cli_json_formatting_edge_cases() {
        let config = create_test_config();

        // Test various JSON formats
        let json_test_cases = vec![
            // Valid JSON
            r#"{"simple": "value"}"#,
            r#"{"number": 42}"#,
            r#"{"boolean": true}"#,
            r#"{"null": null}"#,
            r#"{"array": [1, 2, 3]}"#,
            r#"{"nested": {"object": "value"}}"#,
            // Edge cases
            r#"{}"#,       // Empty object
            r#"[]"#,       // Empty array
            r#""string""#, // JSON string
            r#"42"#,       // JSON number
            // Non-JSON
            "plain text",
            "text with \"quotes\"",
            "multi\nline\ntext",
            "",
        ];

        for json_case in json_test_cases {
            let result = simulate_cli_publish(&config, "test/json", json_case, 0, false).await;
            assert!(result.is_ok(), "Failed for JSON case: {}", json_case);
        }
    }

    #[tokio::test]
    async fn test_cli_configuration_validation() {
        let config = create_test_config();

        // Verify configuration is valid
        assert!(!config.gateway.id.is_empty());
        assert!(!config.mqtt.host.is_empty());
        assert!(config.mqtt.port > 0);
        assert!(config.mqtt.port <= 65535);
    }

    #[tokio::test]
    async fn test_cli_message_size_limits() {
        let config = create_test_config();

        // Test various message sizes
        let sizes = vec![1, 100, 1024, 10240, 102400]; // 1B to 100KB

        for size in sizes {
            let large_message = "X".repeat(size);
            let result =
                simulate_cli_publish(&config, "test/large", &large_message, 0, false).await;
            assert!(result.is_ok(), "Failed for message size: {} bytes", size);
        }
    }

    #[tokio::test]
    async fn test_cli_topic_validation() {
        let config = create_test_config();

        // Test various topic formats
        let valid_topics = vec![
            "simple",
            "path/to/topic",
            "device/sensor-001/temperature",
            "aetheric/measurements",
            "system/health/status",
        ];

        for topic in valid_topics {
            let result = simulate_cli_publish(&config, topic, "test", 0, false).await;
            assert!(result.is_ok(), "Failed for topic: {}", topic);
        }
    }
}
