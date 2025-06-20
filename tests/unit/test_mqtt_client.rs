use aetheric_edge::mqtt::client::MqttClient;
use aetheric_edge::mqtt::messages::*;
use aetheric_edge::mqtt::topics::TopicBuilder;
use std::collections::HashMap;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_mqtt_client_creation() {
    let (command_sender, _command_receiver) = mpsc::unbounded_channel();

    let result = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-gateway".to_string(),
        command_sender,
    )
    .await;

    assert!(result.is_ok());
    let (mqtt_client, _event_loop) = result.unwrap();

    // Test that topic builder has correct gateway ID
    let topic_builder = mqtt_client.topic_builder();
    assert_eq!(topic_builder.gateway_id(), "test-gateway");
}

#[tokio::test]
async fn test_mqtt_client_topic_generation() {
    let (command_sender, _command_receiver) = mpsc::unbounded_channel();

    let (mqtt_client, _event_loop) = MqttClient::new(
        "localhost".to_string(),
        1883,
        "test-device-001".to_string(),
        command_sender,
    )
    .await
    .unwrap();

    let topic_builder = mqtt_client.topic_builder();

    // Test various topic generations
    assert_eq!(topic_builder.health(), "ae/test-device-001/health");
    assert_eq!(topic_builder.commands(), "ae/test-device-001/cmd/+");
    assert_eq!(
        topic_builder.command_response("cmd-123"),
        "ae/test-device-001/cmd/cmd-123/response"
    );
}

#[tokio::test]
async fn test_health_message_serialization() {
    let health_msg = HealthMessage {
        status: HealthStatus::Up,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        gateway_id: "test-gateway".to_string(),
        uptime_seconds: 3600,
        memory_usage_mb: 512,
        cpu_usage_percent: 25.5,
    };

    let json = serde_json::to_string(&health_msg).unwrap();
    assert!(json.contains("up"));
    assert!(json.contains("test-gateway"));
    assert!(json.contains("3600"));
    assert!(json.contains("25.5"));

    // Test deserialization
    let deserialized: HealthMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized.status, HealthStatus::Up));
    assert_eq!(deserialized.gateway_id, "test-gateway");
    assert_eq!(deserialized.uptime_seconds, 3600);
    assert_eq!(deserialized.memory_usage_mb, 512);
    assert_eq!(deserialized.cpu_usage_percent, 25.5);
}

#[tokio::test]
async fn test_command_message_serialization() {
    let mut params = HashMap::new();
    params.insert(
        "test_param".to_string(),
        serde_json::Value::String("test_value".to_string()),
    );

    let command_msg = CommandMessage {
        id: "cmd-123".to_string(),
        command: CommandType::Health,
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        parameters: params,
    };

    let json = serde_json::to_string(&command_msg).unwrap();
    assert!(json.contains("cmd-123"));
    assert!(json.contains("health"));
    assert!(json.contains("test_param"));
    assert!(json.contains("test_value"));

    // Test deserialization
    let deserialized: CommandMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "cmd-123");
    assert!(matches!(deserialized.command, CommandType::Health));
    assert!(deserialized.parameters.contains_key("test_param"));
}

#[tokio::test]
async fn test_plugin_install_command_serialization() {
    let source = PluginSource::Url {
        url: "https://example.com/plugin.bin".to_string(),
        checksum: Some("abc123".to_string()),
        checksum_type: Some("md5".to_string()),
    };

    let mut env = HashMap::new();
    env.insert("PLUGIN_ENV".to_string(), "production".to_string());

    let config = PluginConfig {
        name: "test-plugin".to_string(),
        version: "1.0.0".to_string(),
        description: Some("Test plugin".to_string()),
        plugin_type: PluginType::Binary,
        auto_start: true,
        environment: env,
        dependencies: vec!["dep1".to_string()],
        ports: vec![8080],
        volumes: vec![],
        command_args: vec!["--verbose".to_string()],
    };

    let command = CommandType::Install {
        plugin_name: "test-plugin".to_string(),
        source,
        config: Some(config),
    };

    let json = serde_json::to_string(&command).unwrap();
    assert!(json.contains("install"));
    assert!(json.contains("test-plugin"));
    assert!(json.contains("https://example.com/plugin.bin"));
    assert!(json.contains("abc123"));
    assert!(json.contains("PLUGIN_ENV"));
    assert!(json.contains("binary"));

    // Test deserialization
    let deserialized: CommandType = serde_json::from_str(&json).unwrap();
    match deserialized {
        CommandType::Install {
            plugin_name,
            source,
            config,
        } => {
            assert_eq!(plugin_name, "test-plugin");
            match source {
                PluginSource::Url {
                    url,
                    checksum,
                    checksum_type,
                } => {
                    assert_eq!(url, "https://example.com/plugin.bin");
                    assert_eq!(checksum, Some("abc123".to_string()));
                    assert_eq!(checksum_type, Some("md5".to_string()));
                }
                _ => panic!("Wrong source type"),
            }
            assert!(config.is_some());
            let config = config.unwrap();
            assert_eq!(config.name, "test-plugin");
            assert!(matches!(config.plugin_type, PluginType::Binary));
            assert!(config.auto_start);
        }
        _ => panic!("Wrong command type"),
    }
}

#[tokio::test]
async fn test_ssh_connect_command_serialization() {
    let command = CommandType::SshConnect {
        session_id: "ssh-session-001".to_string(),
        target_host: Some("192.168.1.100".to_string()),
        target_port: Some(22),
        duration_minutes: Some(60),
    };

    let json = serde_json::to_string(&command).unwrap();
    assert!(json.contains("ssh_connect"));
    assert!(json.contains("ssh-session-001"));
    assert!(json.contains("192.168.1.100"));
    assert!(json.contains("22"));
    assert!(json.contains("60"));

    // Test deserialization
    let deserialized: CommandType = serde_json::from_str(&json).unwrap();
    match deserialized {
        CommandType::SshConnect {
            session_id,
            target_host,
            target_port,
            duration_minutes,
        } => {
            assert_eq!(session_id, "ssh-session-001");
            assert_eq!(target_host, Some("192.168.1.100".to_string()));
            assert_eq!(target_port, Some(22));
            assert_eq!(duration_minutes, Some(60));
        }
        _ => panic!("Wrong command type"),
    }
}

#[tokio::test]
async fn test_ssh_data_command_serialization() {
    let command = CommandType::SshData {
        session_id: "ssh-session-001".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test ssh data"),
        direction: SshDataDirection::Up,
    };

    let json = serde_json::to_string(&command).unwrap();
    assert!(json.contains("ssh_data"));
    assert!(json.contains("ssh-session-001"));
    assert!(json.contains("up"));

    // Test deserialization
    let deserialized: CommandType = serde_json::from_str(&json).unwrap();
    match deserialized {
        CommandType::SshData {
            session_id,
            data,
            direction,
        } => {
            assert_eq!(session_id, "ssh-session-001");
            let decoded_data =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data).unwrap();
            assert_eq!(decoded_data, b"test ssh data");
            assert!(matches!(direction, SshDataDirection::Up));
        }
        _ => panic!("Wrong command type"),
    }
}

#[tokio::test]
async fn test_command_response_serialization() {
    let response = CommandResponse {
        command_id: "cmd-123".to_string(),
        status: CommandStatus::Success,
        message: "Command executed successfully".to_string(),
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        result: Some(serde_json::json!({"output": "Hello World"})),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("cmd-123"));
    assert!(json.contains("success"));
    assert!(json.contains("Command executed successfully"));
    assert!(json.contains("Hello World"));

    // Test deserialization
    let deserialized: CommandResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.command_id, "cmd-123");
    assert!(matches!(deserialized.status, CommandStatus::Success));
    assert_eq!(deserialized.message, "Command executed successfully");
    assert!(deserialized.result.is_some());
    let result = deserialized.result.unwrap();
    assert_eq!(result["output"], "Hello World");
}

#[tokio::test]
async fn test_event_message_serialization() {
    let mut metadata = HashMap::new();
    metadata.insert(
        "component".to_string(),
        serde_json::Value::String("ssh_tunnel".to_string()),
    );
    metadata.insert(
        "session_count".to_string(),
        serde_json::Value::Number(serde_json::Number::from(3)),
    );

    let event = EventMessage {
        id: "event-456".to_string(),
        event_type: "ssh_session_created".to_string(),
        message: "New SSH session established".to_string(),
        timestamp: "2025-06-18T15:30:00Z".to_string(),
        severity: EventSeverity::Info,
        metadata,
    };

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("event-456"));
    assert!(json.contains("ssh_session_created"));
    assert!(json.contains("New SSH session established"));
    assert!(json.contains("info"));
    assert!(json.contains("ssh_tunnel"));

    // Test deserialization
    let deserialized: EventMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "event-456");
    assert_eq!(deserialized.event_type, "ssh_session_created");
    assert_eq!(deserialized.message, "New SSH session established");
    assert!(matches!(deserialized.severity, EventSeverity::Info));
    assert!(deserialized.metadata.contains_key("component"));
    assert!(deserialized.metadata.contains_key("session_count"));
}

#[tokio::test]
async fn test_ota_status_serialization() {
    let ota_status = OtaStatus {
        current_version: "1.0.0".to_string(),
        target_version: Some("1.1.0".to_string()),
        status: OtaUpdateStatus::Downloading,
        progress_percent: Some(45),
        message: "Downloading update package".to_string(),
        timestamp: "2025-06-18T15:30:00Z".to_string(),
    };

    let json = serde_json::to_string(&ota_status).unwrap();
    assert!(json.contains("1.0.0"));
    assert!(json.contains("1.1.0"));
    assert!(json.contains("downloading"));
    assert!(json.contains("45"));
    assert!(json.contains("Downloading update package"));

    // Test deserialization
    let deserialized: OtaStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.current_version, "1.0.0");
    assert_eq!(deserialized.target_version, Some("1.1.0".to_string()));
    assert!(matches!(deserialized.status, OtaUpdateStatus::Downloading));
    assert_eq!(deserialized.progress_percent, Some(45));
    assert_eq!(deserialized.message, "Downloading update package");
}

#[tokio::test]
async fn test_chunked_plugin_source_serialization() {
    let source = PluginSource::Chunked {
        chunk_id: "upload-123".to_string(),
        total_chunks: 5,
        chunk_index: 2,
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"chunk data"),
        checksum: Some("file_checksum_abc123".to_string()),
    };

    let json = serde_json::to_string(&source).unwrap();
    assert!(json.contains("chunked"));
    assert!(json.contains("upload-123"));
    assert!(json.contains("5"));
    assert!(json.contains("2"));
    assert!(json.contains("file_checksum_abc123"));

    // Test deserialization
    let deserialized: PluginSource = serde_json::from_str(&json).unwrap();
    match deserialized {
        PluginSource::Chunked {
            chunk_id,
            total_chunks,
            chunk_index,
            data,
            checksum,
        } => {
            assert_eq!(chunk_id, "upload-123");
            assert_eq!(total_chunks, 5);
            assert_eq!(chunk_index, 2);
            let decoded_data =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data).unwrap();
            assert_eq!(decoded_data, b"chunk data");
            assert_eq!(checksum, Some("file_checksum_abc123".to_string()));
        }
        _ => panic!("Wrong source type"),
    }
}

#[tokio::test]
async fn test_all_command_types_serialization() {
    let commands = vec![
        CommandType::Health,
        CommandType::List,
        CommandType::SystemRestart,
        CommandType::Remove {
            plugin_name: "test".to_string(),
        },
        CommandType::Start {
            plugin_name: "test".to_string(),
        },
        CommandType::Stop {
            plugin_name: "test".to_string(),
        },
        CommandType::Restart {
            plugin_name: "test".to_string(),
        },
        CommandType::Status {
            plugin_name: Some("test".to_string()),
        },
        CommandType::Status { plugin_name: None },
        CommandType::SshDisconnect {
            session_id: "session-1".to_string(),
        },
        CommandType::SshHeartbeat {
            session_id: "session-1".to_string(),
        },
        CommandType::OtaUpdate {
            version: "2.0.0".to_string(),
            url: "https://example.com/update.bin".to_string(),
            checksum: Some("update_checksum".to_string()),
        },
    ];

    for command in commands {
        let json = serde_json::to_string(&command).unwrap();
        let deserialized: CommandType = serde_json::from_str(&json).unwrap();

        // Basic check that serialization/deserialization preserves command type
        match (&command, &deserialized) {
            (CommandType::Health, CommandType::Health) => {}
            (CommandType::List, CommandType::List) => {}
            (CommandType::SystemRestart, CommandType::SystemRestart) => {}
            (CommandType::Remove { plugin_name: n1 }, CommandType::Remove { plugin_name: n2 }) => {
                assert_eq!(n1, n2);
            }
            (CommandType::Start { plugin_name: n1 }, CommandType::Start { plugin_name: n2 }) => {
                assert_eq!(n1, n2);
            }
            (CommandType::Stop { plugin_name: n1 }, CommandType::Stop { plugin_name: n2 }) => {
                assert_eq!(n1, n2);
            }
            (
                CommandType::Restart { plugin_name: n1 },
                CommandType::Restart { plugin_name: n2 },
            ) => {
                assert_eq!(n1, n2);
            }
            (CommandType::Status { plugin_name: n1 }, CommandType::Status { plugin_name: n2 }) => {
                assert_eq!(n1, n2);
            }
            (
                CommandType::SshDisconnect { session_id: s1 },
                CommandType::SshDisconnect { session_id: s2 },
            ) => {
                assert_eq!(s1, s2);
            }
            (
                CommandType::SshHeartbeat { session_id: s1 },
                CommandType::SshHeartbeat { session_id: s2 },
            ) => {
                assert_eq!(s1, s2);
            }
            (
                CommandType::OtaUpdate {
                    version: v1,
                    url: u1,
                    checksum: c1,
                },
                CommandType::OtaUpdate {
                    version: v2,
                    url: u2,
                    checksum: c2,
                },
            ) => {
                assert_eq!(v1, v2);
                assert_eq!(u1, u2);
                assert_eq!(c1, c2);
            }
            _ => panic!("Serialization/deserialization mismatch for command types"),
        }
    }
}

#[tokio::test]
async fn test_topic_builder() {
    let builder = TopicBuilder::new("test-device-123".to_string());

    assert_eq!(builder.gateway_id(), "test-device-123");
    assert_eq!(builder.health(), "ae/test-device-123/health");
    assert_eq!(builder.commands(), "ae/test-device-123/cmd/+");
    assert_eq!(
        builder.command_response("cmd-456"),
        "ae/test-device-123/cmd/cmd-456/response"
    );
    assert_eq!(builder.telemetry(), "ae/test-device-123/telemetry");
    assert_eq!(builder.events(), "ae/test-device-123/events");
    assert_eq!(builder.ota_status(), "ae/test-device-123/ota/status");
    assert_eq!(
        builder.ssh_tunnel("session-789"),
        "ae/test-device-123/ssh/session-789"
    );
}
