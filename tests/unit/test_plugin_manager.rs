use aetheric_edge::agent::plugin_manager::{PluginConfig, PluginManager, PluginSource, PluginType};
use aetheric_edge::config::AethericConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

fn create_test_config_with_temp_dir(temp_dir: &TempDir) -> AethericConfig {
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

fn create_test_plugin_config(name: &str, plugin_type: PluginType) -> PluginConfig {
    PluginConfig {
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

#[tokio::test]
async fn test_plugin_manager_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));

    let plugin_manager = PluginManager::new(config.clone());

    // Test listing plugins (should be empty initially)
    let result = plugin_manager.list_plugins().await.unwrap();
    let plugins_list = result.as_object().unwrap();
    assert!(plugins_list.contains_key("plugins"));
    let plugins = plugins_list["plugins"].as_array().unwrap();
    assert_eq!(plugins.len(), 0);
}

#[tokio::test]
async fn test_install_plugin_from_local() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Create a test binary file
    let test_binary_path = temp_dir.path().join("test_binary");
    tokio::fs::write(&test_binary_path, b"#!/bin/bash\necho 'Hello World'\n")
        .await
        .unwrap();

    let source = PluginSource::Local {
        path: test_binary_path.to_string_lossy().to_string(),
    };

    let plugin_config = create_test_plugin_config("test-local-plugin", PluginType::Binary);

    let result = plugin_manager
        .install_plugin("test-local-plugin", &source, plugin_config)
        .await
        .unwrap();

    assert!(result.as_object().unwrap().contains_key("plugin_name"));
    assert_eq!(result["plugin_name"], "test-local-plugin");
    assert_eq!(result["status"], "installed");
}

#[tokio::test]
async fn test_install_plugin_from_base64() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Create base64 encoded script
    let script_content = b"#!/bin/bash\necho 'Hello from base64 plugin'\n";
    let base64_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, script_content);

    let source = PluginSource::Base64 {
        data: base64_data,
        checksum: None,
        checksum_type: None,
    };

    let plugin_config = create_test_plugin_config("test-base64-plugin", PluginType::Script);

    let result = plugin_manager
        .install_plugin("test-base64-plugin", &source, plugin_config)
        .await
        .unwrap();

    assert_eq!(result["plugin_name"], "test-base64-plugin");
    assert_eq!(result["status"], "installed");

    // Verify the file was created and has correct content
    let installed_path = config
        .plugins
        .install_dir
        .join("test-base64-plugin")
        .join("plugin.sh");
    assert!(installed_path.exists());
    let content = tokio::fs::read(&installed_path).await.unwrap();
    assert_eq!(content, script_content);
}

#[tokio::test]
async fn test_install_plugin_invalid_base64() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    let source = PluginSource::Base64 {
        data: "invalid-base64-data!!!".to_string(),
        checksum: None,
        checksum_type: None,
    };

    let plugin_config = create_test_plugin_config("test-invalid-plugin", PluginType::Binary);

    let result = plugin_manager
        .install_plugin("test-invalid-plugin", &source, plugin_config)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_install_plugin_nonexistent_local_file() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    let source = PluginSource::Local {
        path: "/path/that/does/not/exist".to_string(),
    };

    let plugin_config = create_test_plugin_config("test-nonexistent-plugin", PluginType::Binary);

    let result = plugin_manager
        .install_plugin("test-nonexistent-plugin", &source, plugin_config)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_plugin() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // First install a plugin
    let test_binary_path = temp_dir.path().join("test_binary");
    tokio::fs::write(&test_binary_path, b"#!/bin/bash\necho 'Test'\n")
        .await
        .unwrap();

    let source = PluginSource::Local {
        path: test_binary_path.to_string_lossy().to_string(),
    };

    let plugin_config = create_test_plugin_config("test-remove-plugin", PluginType::Binary);

    let install_result = plugin_manager
        .install_plugin("test-remove-plugin", &source, plugin_config)
        .await
        .unwrap();
    assert_eq!(install_result["status"], "installed");

    // Now remove the plugin
    let remove_result = plugin_manager
        .remove_plugin("test-remove-plugin")
        .await
        .unwrap();
    assert_eq!(remove_result["plugin_name"], "test-remove-plugin");
    assert_eq!(remove_result["status"], "removed");

    // Verify the plugin directory was removed
    let plugin_dir = config.plugins.install_dir.join("test-remove-plugin");
    assert!(!plugin_dir.exists());
}

#[tokio::test]
async fn test_remove_nonexistent_plugin() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    let result = plugin_manager
        .remove_plugin("nonexistent-plugin")
        .await
        .unwrap();
    assert_eq!(result["plugin_name"], "nonexistent-plugin");
    assert_eq!(result["status"], "removed"); // Should not error, just report removed
}

#[tokio::test]
async fn test_get_plugin_status() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Test status for non-existent plugin
    let result = plugin_manager.get_plugin_status("nonexistent-plugin").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_start_stop_restart_nonexistent_plugin() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Test start
    let start_result = plugin_manager.start_plugin("nonexistent-plugin").await;
    assert!(start_result.is_err());

    // Test stop
    let stop_result = plugin_manager.stop_plugin("nonexistent-plugin").await;
    assert!(stop_result.is_err());

    // Test restart
    let restart_result = plugin_manager.restart_plugin("nonexistent-plugin").await;
    assert!(restart_result.is_err());
}

#[tokio::test]
async fn test_chunked_transfer() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Create test data to chunk
    let test_data = b"This is a test file that will be transferred in chunks";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test_data);

    // Split into 2 chunks - ensure proper base64 padding
    // Decode first, split the binary data, then re-encode each chunk
    let decoded_data =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_data).unwrap();
    let chunk_size = decoded_data.len() / 2;
    let chunk1_data = &decoded_data[..chunk_size];
    let chunk2_data = &decoded_data[chunk_size..];
    let chunk1 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk1_data);
    let chunk2 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk2_data);

    let plugin_config = create_test_plugin_config("test-chunked-plugin", PluginType::Binary);

    // Send first chunk
    let source1 = PluginSource::Chunked {
        chunk_id: "test-chunk-transfer".to_string(),
        total_chunks: 2,
        chunk_index: 0,
        data: chunk1,
        checksum: None,
    };

    let result1 = plugin_manager
        .install_plugin("test-chunked-plugin", &source1, plugin_config.clone())
        .await
        .unwrap();
    assert_eq!(result1["status"], "chunk_received");

    // Send second chunk (final)
    let source2 = PluginSource::Chunked {
        chunk_id: "test-chunk-transfer".to_string(),
        total_chunks: 2,
        chunk_index: 1,
        data: chunk2,
        checksum: None,
    };

    let result2 = plugin_manager
        .install_plugin("test-chunked-plugin", &source2, plugin_config)
        .await
        .unwrap();
    assert_eq!(result2["status"], "installed");

    // Verify the complete file was created - since the test data is plain text, it defaults to "plugin.bin"
    let installed_path = config
        .plugins
        .install_dir
        .join("test-chunked-plugin")
        .join("plugin.bin");
    assert!(installed_path.exists());
    let content = tokio::fs::read(&installed_path).await.unwrap();
    assert_eq!(content, test_data);
}

#[tokio::test]
async fn test_chunked_transfer_out_of_order() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    let test_data = b"Test data for out of order chunks";
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, test_data);

    // Split into 2 chunks - ensure proper base64 padding
    // Decode first, split the binary data, then re-encode each chunk
    let decoded_data =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_data).unwrap();
    let chunk_size = decoded_data.len() / 2;
    let chunk1_data = &decoded_data[..chunk_size];
    let chunk2_data = &decoded_data[chunk_size..];
    let chunk1 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk1_data);
    let chunk2 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk2_data);

    let plugin_config = create_test_plugin_config("test-ooo-plugin", PluginType::Binary);

    // Send second chunk first
    let source2 = PluginSource::Chunked {
        chunk_id: "test-ooo-transfer".to_string(),
        total_chunks: 2,
        chunk_index: 1,
        data: chunk2,
        checksum: None,
    };

    let result2 = plugin_manager
        .install_plugin("test-ooo-plugin", &source2, plugin_config.clone())
        .await
        .unwrap();
    assert_eq!(result2["status"], "chunk_received");

    // Send first chunk
    let source1 = PluginSource::Chunked {
        chunk_id: "test-ooo-transfer".to_string(),
        total_chunks: 2,
        chunk_index: 0,
        data: chunk1,
        checksum: None,
    };

    let result1 = plugin_manager
        .install_plugin("test-ooo-plugin", &source1, plugin_config)
        .await
        .unwrap();
    assert_eq!(result1["status"], "installed");

    // Verify the complete file was created correctly - since the test data is plain text, it defaults to "plugin.bin"
    let installed_path = config
        .plugins
        .install_dir
        .join("test-ooo-plugin")
        .join("plugin.bin");
    assert!(installed_path.exists());
    let content = tokio::fs::read(&installed_path).await.unwrap();
    assert_eq!(content, test_data);
}

#[tokio::test]
async fn test_plugin_config_serialization() {
    let mut env = HashMap::new();
    env.insert("TEST_VAR".to_string(), "test_value".to_string());

    let config = PluginConfig {
        name: "test-plugin".to_string(),
        version: "2.1.0".to_string(),
        description: Some("Test plugin for serialization".to_string()),
        plugin_type: PluginType::Docker,
        auto_start: true,
        environment: env,
        dependencies: vec!["dep1".to_string(), "dep2".to_string()],
        ports: vec![8080, 8081],
        volumes: vec!["/host:/container".to_string()],
        command_args: vec![
            "--verbose".to_string(),
            "--config=/app/config.json".to_string(),
        ],
    };

    // Test serialization
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("test-plugin"));
    assert!(json.contains("docker"));
    assert!(json.contains("TEST_VAR"));

    // Test deserialization
    let deserialized: PluginConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, config.name);
    assert_eq!(deserialized.version, config.version);
    assert!(matches!(deserialized.plugin_type, PluginType::Docker));
    assert_eq!(deserialized.auto_start, config.auto_start);
    assert_eq!(deserialized.environment, config.environment);
    assert_eq!(deserialized.dependencies, config.dependencies);
    assert_eq!(deserialized.ports, config.ports);
    assert_eq!(deserialized.volumes, config.volumes);
    assert_eq!(deserialized.command_args, config.command_args);
}

#[tokio::test]
async fn test_list_plugins_with_installed_plugins() {
    let temp_dir = TempDir::new().unwrap();
    let config = Arc::new(create_test_config_with_temp_dir(&temp_dir));
    let plugin_manager = PluginManager::new(config.clone());

    // Install a test plugin
    let test_binary_path = temp_dir.path().join("test_binary");
    tokio::fs::write(&test_binary_path, b"#!/bin/bash\necho 'Test'\n")
        .await
        .unwrap();

    let source = PluginSource::Local {
        path: test_binary_path.to_string_lossy().to_string(),
    };

    let plugin_config = create_test_plugin_config("list-test-plugin", PluginType::Binary);

    plugin_manager
        .install_plugin("list-test-plugin", &source, plugin_config)
        .await
        .unwrap();

    // List plugins should now show our installed plugin
    let result = plugin_manager.list_plugins().await.unwrap();
    let plugins_list = result.as_object().unwrap();
    assert!(plugins_list.contains_key("plugins"));
    let plugins = plugins_list["plugins"].as_array().unwrap();
    assert!(!plugins.is_empty());

    // Find our plugin in the list
    let our_plugin = plugins
        .iter()
        .find(|p| p["plugin_name"] == "list-test-plugin");
    assert!(our_plugin.is_some());
    let our_plugin = our_plugin.unwrap();
    assert_eq!(our_plugin["version"], "1.0.0");
    assert_eq!(our_plugin["plugin_type"], "binary");
}
