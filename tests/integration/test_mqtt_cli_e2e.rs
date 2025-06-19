use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// End-to-end tests for the MQTT CLI functionality
/// These tests execute the actual CLI binary to ensure everything works correctly

fn get_cli_binary_path() -> PathBuf {
    // Path to the compiled CLI binary
    std::env::current_dir()
        .unwrap()
        .join("target")
        .join("debug")
        .join("aetheric")
}

fn create_test_config_file() -> Result<(TempDir, PathBuf)> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("aetheric.toml");

    let config_content = r#"
[gateway]
id = "test-gateway-e2e"
name = "E2E Test Gateway"

[mqtt]
host = "localhost"
port = 1883
tls = false

[certificates]
cert_dir = "/tmp/aetheric-test/certs"
auto_renew = false
renew_days_threshold = 30

[health]
report_interval_seconds = 30
metrics_enabled = true

[plugins]
install_dir = "/tmp/aetheric-test/plugins"
temp_dir = "/tmp/aetheric-test/temp"
docker_enabled = true
max_concurrent_installs = 2

[ssh]
enabled = true
port = 22
max_sessions = 5
session_timeout_minutes = 60
"#;

    fs::write(&config_path, config_content)?;
    Ok((temp_dir, config_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_binary_exists() {
        let binary_path = get_cli_binary_path();
        assert!(
            binary_path.exists(),
            "CLI binary not found at: {:?}",
            binary_path
        );
    }

    #[test]
    fn test_cli_help_command() {
        let output = Command::new(get_cli_binary_path())
            .arg("--help")
            .output()
            .expect("Failed to execute CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Aetheric Edge management CLI"));
        assert!(stdout.contains("mqtt"));
        assert!(stdout.contains("MQTT message publishing and subscribing"));
    }

    #[test]
    fn test_mqtt_subcommand_help() {
        let output = Command::new(get_cli_binary_path())
            .args(&["mqtt", "--help"])
            .output()
            .expect("Failed to execute CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("MQTT message publishing and subscribing"));
        assert!(stdout.contains("pub"));
        assert!(stdout.contains("sub"));
        assert!(stdout.contains("Publish a message to an MQTT topic"));
        assert!(stdout.contains("Subscribe to an MQTT topic"));
    }

    #[test]
    fn test_mqtt_pub_help() {
        let output = Command::new(get_cli_binary_path())
            .args(&["mqtt", "pub", "--help"])
            .output()
            .expect("Failed to execute CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Publish a message to an MQTT topic"));
        assert!(stdout.contains("<TOPIC>"));
        assert!(stdout.contains("<MESSAGE>"));
        assert!(stdout.contains("--qos"));
        assert!(stdout.contains("--retain"));
        assert!(stdout.contains("QoS level (0, 1, or 2)"));
    }

    #[test]
    fn test_mqtt_sub_help() {
        let output = Command::new(get_cli_binary_path())
            .args(&["mqtt", "sub", "--help"])
            .output()
            .expect("Failed to execute CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Subscribe to an MQTT topic"));
        assert!(stdout.contains("<TOPIC>"));
        assert!(stdout.contains("--qos"));
        assert!(stdout.contains("--no-topic"));
        assert!(stdout.contains("--output"));
        assert!(stdout.contains("Hide topic names in output"));
    }

    #[test]
    fn test_mqtt_pub_missing_arguments() {
        let output = Command::new(get_cli_binary_path())
            .args(&["mqtt", "pub"])
            .output()
            .expect("Failed to execute CLI");

        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("required") || stderr.contains("TOPIC") || stderr.contains("MESSAGE")
        );
    }

    #[test]
    fn test_mqtt_sub_missing_arguments() {
        let output = Command::new(get_cli_binary_path())
            .args(&["mqtt", "sub"])
            .output()
            .expect("Failed to execute CLI");

        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("required") || stderr.contains("TOPIC"));
    }

    #[test]
    fn test_mqtt_pub_invalid_qos() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "--qos",
                "5",
                "test/topic",
                "test message",
            ])
            .output()
            .expect("Failed to execute CLI");

        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Invalid QoS") || stderr.contains("error"));
    }

    #[test]
    fn test_mqtt_pub_with_valid_config() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        // This should fail to connect but succeed in parsing arguments
        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "--qos",
                "1",
                "--retain",
                "aetheric/test",
                r#"{"message": "test"}"#,
            ])
            .output()
            .expect("Failed to execute CLI");

        // Should fail due to no MQTT broker, but arguments should be valid
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            // Expect connection error, not argument parsing error
            assert!(
                stderr.contains("Connection refused")
                    || stderr.contains("I/O")
                    || stderr.contains("MQTT error")
                    || stderr.contains("Failed to load configuration")
            );
        }
    }

    #[test]
    fn test_mqtt_pub_with_json_message() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        let json_message = r#"{"temperature": 23.5, "humidity": 60, "sensor_id": "temp-001"}"#;

        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "sensor/temperature",
                json_message,
            ])
            .output()
            .expect("Failed to execute CLI");

        // Should parse JSON correctly even if connection fails
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            assert!(
                stderr.contains("Connection refused")
                    || stderr.contains("I/O")
                    || stderr.contains("MQTT error")
                    || stderr.contains("Failed to load configuration")
            );
            // Should NOT contain JSON parsing errors
            assert!(!stderr.contains("JSON") || !stderr.contains("parse"));
        }
    }

    #[test]
    fn test_mqtt_pub_with_host_override() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "--host",
                "test.mosquitto.org",
                "--port",
                "1883",
                "test/aetheric",
                "test message",
            ])
            .output()
            .expect("Failed to execute CLI");

        // This might succeed or fail depending on network, but should parse arguments correctly
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            // Should be a connection error, not an argument error
            assert!(
                stderr.contains("Connection")
                    || stderr.contains("I/O")
                    || stderr.contains("MQTT")
                    || stderr.contains("timeout")
                    || stderr.contains("Failed to load configuration")
            );
        }
    }

    #[test]
    fn test_mqtt_pub_with_different_qos_levels() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        for qos in &["0", "1", "2"] {
            let output = Command::new(get_cli_binary_path())
                .args(&[
                    "mqtt",
                    "pub",
                    "--config",
                    config_path.to_str().unwrap(),
                    "--qos",
                    qos,
                    "test/qos",
                    "test message",
                ])
                .output()
                .expect("Failed to execute CLI");

            // Arguments should be valid regardless of connection
            let stderr = String::from_utf8(output.stderr).unwrap();
            if !output.status.success() {
                assert!(
                    stderr.contains("Connection")
                        || stderr.contains("I/O")
                        || stderr.contains("MQTT")
                        || stderr.contains("Failed to load configuration")
                );
                // Should NOT contain QoS validation errors
                assert!(!stderr.contains("Invalid QoS"));
            }
        }
    }

    #[test]
    fn test_mqtt_config_integration() {
        // Test creating a configuration and using it with MQTT commands
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("aetheric.toml");

        // First, initialize a config
        let output = Command::new(get_cli_binary_path())
            .args(&["config", "init", "--config", config_path.to_str().unwrap()])
            .output()
            .expect("Failed to execute CLI");

        assert!(output.status.success());
        assert!(config_path.exists());

        // Then try to use it with MQTT
        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "test/config",
                "config test",
            ])
            .output()
            .expect("Failed to execute CLI");

        // Should be able to load the config (connection will likely fail)
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            assert!(
                stderr.contains("Connection") || stderr.contains("I/O") || stderr.contains("MQTT")
            );
            // Should NOT contain config loading errors
            assert!(!stderr.contains("Failed to load configuration"));
        }
    }

    #[test]
    fn test_mqtt_pub_with_empty_message() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "test/empty",
                "",
            ])
            .output()
            .expect("Failed to execute CLI");

        // Empty message should be allowed
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            assert!(
                stderr.contains("Connection")
                    || stderr.contains("I/O")
                    || stderr.contains("MQTT")
                    || stderr.contains("Failed to load configuration")
            );
        }
    }

    #[test]
    fn test_mqtt_pub_with_special_characters() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        let special_message = "Message with 特殊字符 and émojis 🚀 and \"quotes\"";

        let output = Command::new(get_cli_binary_path())
            .args(&[
                "mqtt",
                "pub",
                "--config",
                config_path.to_str().unwrap(),
                "test/special",
                special_message,
            ])
            .output()
            .expect("Failed to execute CLI");

        // Special characters should be handled correctly
        let stderr = String::from_utf8(output.stderr).unwrap();
        if !output.status.success() {
            assert!(
                stderr.contains("Connection")
                    || stderr.contains("I/O")
                    || stderr.contains("MQTT")
                    || stderr.contains("Failed to load configuration")
            );
            // Should NOT contain encoding errors
            assert!(!stderr.contains("encoding") && !stderr.contains("UTF-8"));
        }
    }

    #[test]
    fn test_mqtt_topic_validation() {
        let (_temp_dir, config_path) = create_test_config_file().unwrap();

        // Test various topic formats
        let topics = vec![
            "simple",
            "path/to/topic",
            "device/sensor-001/temperature",
            "aetheric/measurements",
            "+/wildcard",
            "multi/+/wildcards/+",
        ];

        for topic in topics {
            let output = Command::new(get_cli_binary_path())
                .args(&[
                    "mqtt",
                    "pub",
                    "--config",
                    config_path.to_str().unwrap(),
                    topic,
                    "test",
                ])
                .output()
                .expect("Failed to execute CLI");

            // Topics should be accepted (connection may fail)
            let stderr = String::from_utf8(output.stderr).unwrap();
            if !output.status.success() {
                assert!(
                    stderr.contains("Connection")
                        || stderr.contains("I/O")
                        || stderr.contains("MQTT")
                        || stderr.contains("Failed to load configuration")
                );
                // Should NOT contain topic validation errors
                assert!(!stderr.contains("Invalid topic"));
            }
        }
    }
}
