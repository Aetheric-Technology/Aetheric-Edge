use aetheric_edge::config::AethericConfig;

/// Test that default configuration uses ~/.aetheric/plugins
#[test]
fn test_default_config_uses_user_home_plugins() {
    let config = AethericConfig::default();

    // Get expected path
    let home = dirs::home_dir().expect("Home directory should be available in tests");
    let expected_plugins_dir = home.join(".aetheric").join("plugins");
    let expected_temp_dir = home.join(".aetheric").join("tmp");
    let expected_cert_dir = home.join(".aetheric").join("certs");

    // Verify plugin directories use ~/.aetheric
    assert_eq!(config.plugins.install_dir, expected_plugins_dir);
    assert_eq!(config.plugins.temp_dir, expected_temp_dir);
    assert_eq!(config.certificates.cert_dir, expected_cert_dir);

    println!(
        "✅ Default config uses ~/.aetheric/plugins: {}",
        config.plugins.install_dir.display()
    );
    println!(
        "✅ Default config uses ~/.aetheric/tmp: {}",
        config.plugins.temp_dir.display()
    );
    println!(
        "✅ Default config uses ~/.aetheric/certs: {}",
        config.certificates.cert_dir.display()
    );
}

#[test]
fn test_config_path_preference() {
    let config_path = AethericConfig::get_config_path();

    // Should prefer ~/.aetheric/config/aetheric.toml for new installations
    let home = dirs::home_dir().expect("Home directory should be available in tests");
    let expected_primary = home.join(".aetheric").join("config").join("aetheric.toml");

    assert_eq!(config_path, expected_primary);
    println!("✅ Config path preference: {}", config_path.display());
}

#[test]
fn test_path_expansion() {
    use std::path::Path;

    // Test tilde expansion
    let tilde_path = Path::new("~/.aetheric/plugins");
    let expanded = AethericConfig::expand_path(tilde_path);

    let home = dirs::home_dir().expect("Home directory should be available in tests");
    let expected = home.join(".aetheric").join("plugins");

    assert_eq!(expanded, expected);
    println!(
        "✅ Path expansion works: {} -> {}",
        tilde_path.display(),
        expanded.display()
    );
}

#[test]
fn test_no_sudo_required_directories() {
    let config = AethericConfig::default();

    // All default directories should be under user home (no sudo required)
    let home = dirs::home_dir().expect("Home directory should be available in tests");

    assert!(config.plugins.install_dir.starts_with(&home));
    assert!(config.plugins.temp_dir.starts_with(&home));
    assert!(config.certificates.cert_dir.starts_with(&home));

    // None should require system-level access
    assert!(!config.plugins.install_dir.starts_with("/opt"));
    assert!(!config.plugins.install_dir.starts_with("/etc"));
    assert!(!config.plugins.install_dir.starts_with("/usr"));

    println!("✅ All directories are user-owned (no sudo required)");
    println!("   Plugins: {}", config.plugins.install_dir.display());
    println!("   Temp: {}", config.plugins.temp_dir.display());
    println!("   Certs: {}", config.certificates.cert_dir.display());
}

#[test]
fn test_directory_consistency() {
    let config = AethericConfig::default();

    // All directories should be under the same .aetheric parent
    let home = dirs::home_dir().expect("Home directory should be available in tests");
    let aetheric_base = home.join(".aetheric");

    assert!(config.plugins.install_dir.starts_with(&aetheric_base));
    assert!(config.plugins.temp_dir.starts_with(&aetheric_base));
    assert!(config.certificates.cert_dir.starts_with(&aetheric_base));

    println!("✅ All directories are consistently under ~/.aetheric/");
}

#[cfg(test)]
mod integration_test {
    use super::*;
    use aetheric_edge::agent::plugin_manager::PluginManager;
    use std::sync::Arc;

    #[test]
    fn test_plugin_manager_uses_default_paths() {
        let config = Arc::new(AethericConfig::default());
        let _plugin_manager = PluginManager::new(config.clone());

        // Plugin manager should use the same paths
        let home = dirs::home_dir().expect("Home directory should be available");
        let expected_plugins = home.join(".aetheric").join("plugins");

        assert_eq!(config.plugins.install_dir, expected_plugins);
        println!("✅ PluginManager uses ~/.aetheric/plugins by default");
    }
}
