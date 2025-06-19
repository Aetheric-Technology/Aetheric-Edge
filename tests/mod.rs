// Test modules for Aetheric Edge
// This file organizes all unit and integration tests

pub mod common;

pub mod unit {
    pub mod test_command_handler;
    pub mod test_default_paths;
    pub mod test_mqtt_cli;
    pub mod test_mqtt_client;
    pub mod test_mqtt_error_handling;
    pub mod test_plugin_manager;
    pub mod test_ssh_error_handling;
    pub mod test_ssh_security;
    pub mod test_ssh_sessions;
    pub mod test_ssh_stress;
    pub mod test_ssh_tunnel;
}

pub mod integration {
    pub mod test_full_system;
    pub mod test_mqtt_cli_e2e;
    pub mod test_mqtt_integration;
    pub mod test_plugin_installation;
}

pub mod extreme {
    pub mod extreme_stress_tests;
}

// Test configuration and constants
pub mod test_config {
    pub const TEST_GATEWAY_ID: &str = "test-gateway-001";
    pub const TEST_MQTT_HOST: &str = "localhost";
    pub const TEST_MQTT_PORT: u16 = 1883;
    pub const TEST_SSH_PORT: u16 = 22;
    pub const TEST_PLUGIN_VERSION: &str = "1.0.0";

    /// Default test timeout for async operations
    pub const TEST_TIMEOUT_MS: u64 = 5000;

    /// Test data for chunked transfers
    pub fn get_test_chunk_data() -> &'static [u8] {
        b"This is test data for chunked transfer testing. It contains multiple lines and should be long enough to warrant chunking into multiple pieces."
    }

    /// Test SSH session data
    pub fn get_test_ssh_data() -> &'static [u8] {
        b"ssh test data: echo 'hello world'; ls -la; pwd"
    }
}
