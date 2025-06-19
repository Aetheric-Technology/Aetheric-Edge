use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde_json::Value;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::time::{timeout, Duration};
use tracing::{error, info};
use tracing_subscriber;

mod certs;
mod config;

use certs::CertificateManager;
use config::AethericConfig;

#[derive(Parser)]
#[command(name = "aetheric")]
#[command(about = "Aetheric Edge management CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(long, help = "Certificate directory path")]
    cert_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Certificate management commands
    Cert {
        #[command(subcommand)]
        action: CertCommands,
    },
    /// Configuration management commands
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// MQTT message publishing and subscribing
    Mqtt {
        #[command(subcommand)]
        action: MqttCommands,
    },
}

#[derive(Subcommand)]
enum CertCommands {
    /// Create a new device certificate
    Create {
        #[arg(help = "Device ID (will be used as CN)")]
        device_id: String,
        #[arg(long, help = "Subject Alternative Names")]
        san: Vec<String>,
    },
    /// Create a certificate signing request
    Csr {
        #[arg(help = "Device ID (will be used as CN)")]
        device_id: String,
        #[arg(long, help = "Subject Alternative Names")]
        san: Vec<String>,
    },
    /// Install a certificate from a PEM file
    Install {
        #[arg(help = "Path to certificate PEM file")]
        cert_file: PathBuf,
    },
    /// Install a CA certificate
    InstallCa {
        #[arg(help = "Path to CA certificate PEM file")]
        ca_file: PathBuf,
    },
    /// Show certificate information
    Show,
    /// Check certificate expiry
    Check {
        #[arg(long, default_value = "30", help = "Days threshold for expiry warning")]
        days: i64,
    },
    /// Renew the device certificate
    Renew {
        #[arg(help = "Device ID (will be used as CN)")]
        device_id: String,
        #[arg(long, help = "Subject Alternative Names")]
        san: Vec<String>,
    },
    /// Remove device certificates
    Remove,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Generate default configuration
    Init {
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
    /// Show current configuration
    Show {
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
    /// Get a configuration value
    Get {
        #[arg(help = "Configuration key (e.g., gateway.id)")]
        key: String,
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
    /// Set a configuration value
    Set {
        #[arg(help = "Configuration key (e.g., gateway.id)")]
        key: String,
        #[arg(help = "Configuration value")]
        value: String,
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MqttCommands {
    /// Publish a message to an MQTT topic
    Pub {
        #[arg(help = "Topic to publish to")]
        topic: String,
        #[arg(help = "Message payload")]
        message: String,
        #[arg(short, long, default_value = "0", help = "QoS level (0, 1, or 2)")]
        qos: u8,
        #[arg(short, long, help = "Retain message")]
        retain: bool,
        #[arg(long, help = "MQTT broker host (overrides config)")]
        host: Option<String>,
        #[arg(long, help = "MQTT broker port (overrides config)")]
        port: Option<u16>,
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
    /// Subscribe to an MQTT topic
    Sub {
        #[arg(help = "Topic to subscribe to")]
        topic: String,
        #[arg(short, long, default_value = "0", help = "QoS level (0, 1, or 2)")]
        qos: u8,
        #[arg(long, help = "Hide topic names in output")]
        no_topic: bool,
        #[arg(
            short,
            long,
            help = "Output file to write messages (stdout if not specified)"
        )]
        output: Option<PathBuf>,
        #[arg(long, help = "MQTT broker host (overrides config)")]
        host: Option<String>,
        #[arg(long, help = "MQTT broker port (overrides config)")]
        port: Option<u16>,
        #[arg(long, help = "Configuration file path")]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_filter = if cli.verbose { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_target(false)
        .init();

    let result = match cli.command {
        Commands::Cert { action } => handle_cert_commands(action, cli.cert_dir).await,
        Commands::Config { action } => handle_config_commands(action).await,
        Commands::Mqtt { action } => handle_mqtt_commands(action).await,
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn handle_cert_commands(action: CertCommands, cert_dir: Option<PathBuf>) -> Result<()> {
    let cert_dir = cert_dir.unwrap_or_else(|| CertificateManager::get_default_cert_dir());
    let cert_manager = CertificateManager::new(cert_dir);

    match action {
        CertCommands::Create { device_id, san } => {
            cert_manager
                .create_device_certificate(&device_id, san)
                .await?;
        }
        CertCommands::Csr { device_id, san } => {
            cert_manager
                .create_certificate_signing_request(&device_id, san)
                .await?;
        }
        CertCommands::Install { cert_file } => {
            let cert_pem = std::fs::read_to_string(&cert_file)
                .with_context(|| format!("Failed to read certificate file: {:?}", cert_file))?;
            cert_manager.install_certificate(&cert_pem).await?;
        }
        CertCommands::InstallCa { ca_file } => {
            let ca_pem = std::fs::read_to_string(&ca_file)
                .with_context(|| format!("Failed to read CA certificate file: {:?}", ca_file))?;
            cert_manager.install_ca_certificate(&ca_pem).await?;
        }
        CertCommands::Show => {
            if let Some(cert_info) = cert_manager.get_certificate_info().await? {
                println!("Certificate Information:");
                println!("  Subject: {}", cert_info.subject);
                println!("  Issuer: {}", cert_info.issuer);
                println!(
                    "  Valid from: {}",
                    cert_info.not_before.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!(
                    "  Valid until: {}",
                    cert_info.not_after.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!("  Serial: {}", cert_info.serial_number);
                println!(
                    "  Status: {}",
                    if cert_info.is_valid {
                        "Valid"
                    } else {
                        "Invalid"
                    }
                );
                println!("  Days until expiry: {}", cert_info.days_until_expiry);

                if let Some(device_id) = cert_manager.extract_device_id_from_cert()? {
                    println!("  Device ID: {}", device_id);
                }
            } else {
                println!("No device certificate found");
            }
        }
        CertCommands::Check { days } => {
            let is_valid = cert_manager.check_certificate_expiry(days).await?;
            if is_valid {
                println!("Certificate is valid and not expiring within {} days", days);
            } else {
                println!(
                    "Certificate is either missing or expiring within {} days",
                    days
                );
                std::process::exit(1);
            }
        }
        CertCommands::Renew { device_id, san } => {
            cert_manager.renew_certificate(&device_id, san).await?;
        }
        CertCommands::Remove => {
            cert_manager.remove_certificates().await?;
        }
    }

    Ok(())
}

async fn handle_config_commands(action: ConfigCommands) -> Result<()> {
    match action {
        ConfigCommands::Init { config } => {
            let config_path = config.unwrap_or_else(|| AethericConfig::get_config_path());
            let default_config = AethericConfig::default();
            default_config
                .save_to_file(&config_path)
                .context("Failed to create default configuration")?;
            info!("Default configuration created at: {:?}", config_path);
        }
        ConfigCommands::Show { config } => {
            let config_path = config.unwrap_or_else(|| AethericConfig::get_config_path());
            let config = AethericConfig::load_from_file(&config_path)
                .context("Failed to load configuration")?;

            let toml_str =
                toml::to_string_pretty(&config).context("Failed to serialize configuration")?;
            println!("{}", toml_str);
        }
        ConfigCommands::Get { key, config } => {
            let config_path = config.unwrap_or_else(|| AethericConfig::get_config_path());
            let config = AethericConfig::load_from_file(&config_path)
                .context("Failed to load configuration")?;

            let value = get_config_value(&config, &key)?;
            println!("{}", value);
        }
        ConfigCommands::Set { key, value, config } => {
            let config_path = config.unwrap_or_else(|| AethericConfig::get_config_path());
            let mut config = AethericConfig::load_from_file(&config_path)
                .context("Failed to load configuration")?;

            set_config_value(&mut config, &key, &value)?;
            config
                .save_to_file(&config_path)
                .context("Failed to save configuration")?;

            info!("Configuration updated: {} = {}", key, value);
        }
    }

    Ok(())
}

fn get_config_value(config: &AethericConfig, key: &str) -> Result<String> {
    match key {
        "gateway.id" => Ok(config.gateway.id.clone()),
        "gateway.name" => Ok(config.gateway.name.clone().unwrap_or_default()),
        "gateway.location" => Ok(config.gateway.location.clone().unwrap_or_default()),
        "gateway.description" => Ok(config.gateway.description.clone().unwrap_or_default()),
        "mqtt.host" => Ok(config.mqtt.host.clone()),
        "mqtt.port" => Ok(config.mqtt.port.to_string()),
        "mqtt.username" => Ok(config.mqtt.username.clone().unwrap_or_default()),
        "mqtt.tls" => Ok(config.mqtt.tls.to_string()),
        "health.report_interval_seconds" => Ok(config.health.report_interval_seconds.to_string()),
        "health.metrics_enabled" => Ok(config.health.metrics_enabled.to_string()),
        "plugins.install_dir" => Ok(config.plugins.install_dir.to_string_lossy().to_string()),
        "plugins.temp_dir" => Ok(config.plugins.temp_dir.to_string_lossy().to_string()),
        "plugins.docker_enabled" => Ok(config.plugins.docker_enabled.to_string()),
        "plugins.max_concurrent_installs" => Ok(config.plugins.max_concurrent_installs.to_string()),
        "certificates.cert_dir" => Ok(config.certificates.cert_dir.to_string_lossy().to_string()),
        "certificates.auto_renew" => Ok(config.certificates.auto_renew.to_string()),
        "certificates.renew_days_threshold" => {
            Ok(config.certificates.renew_days_threshold.to_string())
        }
        "ssh.enabled" => Ok(config.ssh.enabled.to_string()),
        "ssh.port" => Ok(config.ssh.port.to_string()),
        "ssh.max_sessions" => Ok(config.ssh.max_sessions.to_string()),
        "ssh.session_timeout_minutes" => Ok(config.ssh.session_timeout_minutes.to_string()),
        _ => anyhow::bail!("Unknown configuration key: {}", key),
    }
}

fn set_config_value(config: &mut AethericConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "gateway.id" => config.gateway.id = value.to_string(),
        "gateway.name" => {
            config.gateway.name = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "gateway.location" => {
            config.gateway.location = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "gateway.description" => {
            config.gateway.description = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "mqtt.host" => config.mqtt.host = value.to_string(),
        "mqtt.port" => config.mqtt.port = value.parse().context("Invalid port number")?,
        "mqtt.username" => {
            config.mqtt.username = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "mqtt.tls" => config.mqtt.tls = value.parse().context("Invalid boolean value")?,
        "health.report_interval_seconds" => {
            config.health.report_interval_seconds = value.parse().context("Invalid number")?
        }
        "health.metrics_enabled" => {
            config.health.metrics_enabled = value.parse().context("Invalid boolean value")?
        }
        "plugins.install_dir" => config.plugins.install_dir = value.into(),
        "plugins.temp_dir" => config.plugins.temp_dir = value.into(),
        "plugins.docker_enabled" => {
            config.plugins.docker_enabled = value.parse().context("Invalid boolean value")?
        }
        "plugins.max_concurrent_installs" => {
            config.plugins.max_concurrent_installs = value.parse().context("Invalid number")?
        }
        "certificates.cert_dir" => config.certificates.cert_dir = value.into(),
        "certificates.auto_renew" => {
            config.certificates.auto_renew = value.parse().context("Invalid boolean value")?
        }
        "certificates.renew_days_threshold" => {
            config.certificates.renew_days_threshold = value.parse().context("Invalid number")?
        }
        "ssh.enabled" => config.ssh.enabled = value.parse().context("Invalid boolean value")?,
        "ssh.port" => config.ssh.port = value.parse().context("Invalid port number")?,
        "ssh.max_sessions" => config.ssh.max_sessions = value.parse().context("Invalid number")?,
        "ssh.session_timeout_minutes" => {
            config.ssh.session_timeout_minutes = value.parse().context("Invalid number")?
        }
        _ => anyhow::bail!("Unknown configuration key: {}", key),
    }
    Ok(())
}

async fn handle_mqtt_commands(action: MqttCommands) -> Result<()> {
    match action {
        MqttCommands::Pub {
            topic,
            message,
            qos,
            retain,
            host,
            port,
            config,
        } => handle_mqtt_publish(topic, message, qos, retain, host, port, config).await,
        MqttCommands::Sub {
            topic,
            qos,
            no_topic,
            output,
            host,
            port,
            config,
        } => handle_mqtt_subscribe(topic, qos, no_topic, output, host, port, config).await,
    }
}

async fn handle_mqtt_publish(
    topic: String,
    message: String,
    qos: u8,
    retain: bool,
    host_override: Option<String>,
    port_override: Option<u16>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    // Load configuration
    let config_path = config_path.unwrap_or_else(|| AethericConfig::get_config_path());
    let config = AethericConfig::load_from_file(&config_path)
        .context("Failed to load configuration. Run 'aetheric config init' first.")?;

    // Use overrides or config values
    let host = host_override.unwrap_or_else(|| config.mqtt.host.clone());
    let port = port_override.unwrap_or(config.mqtt.port);

    // Validate QoS
    let qos_level = match qos {
        0 => QoS::AtMostOnce,
        1 => QoS::AtLeastOnce,
        2 => QoS::ExactlyOnce,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid QoS level: {}. Must be 0, 1, or 2",
                qos
            ))
        }
    };

    // Validate and potentially format JSON message
    let formatted_message = format_message(&message)?;

    // Set up MQTT client
    let client_id = format!("aetheric-cli-pub-{}", uuid::Uuid::new_v4());
    let mut mqttoptions = MqttOptions::new(client_id, host.clone(), port);
    mqttoptions.set_keep_alive(Duration::from_secs(30));

    // Configure credentials if provided
    if let Some(username) = &config.mqtt.username {
        if let Some(password) = &config.mqtt.password {
            mqttoptions.set_credentials(username, password);
        }
    }

    // Configure TLS if enabled
    if config.mqtt.tls {
        configure_tls(&mut mqttoptions, &config)?;
    }

    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    // Publish message
    info!("Publishing to topic '{}' on {}:{}", topic, host, port);
    client
        .publish(&topic, qos_level, retain, formatted_message.as_bytes())
        .await
        .context("Failed to publish message")?;

    // Wait for publish to complete with timeout
    let publish_timeout = Duration::from_secs(10);
    let result = timeout(publish_timeout, async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    info!("Connected to MQTT broker");
                }
                Ok(Event::Incoming(Packet::PubAck(_))) => {
                    info!("Message published successfully");
                    return Ok(());
                }
                Ok(Event::Incoming(Packet::PubRec(_))) => {
                    info!("Message received by broker (QoS 2 - part 1)");
                }
                Ok(Event::Incoming(Packet::PubComp(_))) => {
                    info!("Message published successfully (QoS 2 - complete)");
                    return Ok(());
                }
                Ok(Event::Outgoing(_)) => {
                    // Outgoing events, continue polling
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("MQTT error: {}", e));
                }
                _ => {}
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            println!("✓ Message published to topic '{}'", topic);
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // For QoS 0, we might not get an ack, so we consider it successful after timeout
            if qos == 0 {
                println!(
                    "✓ Message sent to topic '{}' (QoS 0 - fire and forget)",
                    topic
                );
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Timeout waiting for publish acknowledgment"
                ))
            }
        }
    }
}

async fn handle_mqtt_subscribe(
    topic: String,
    qos: u8,
    no_topic: bool,
    output_file: Option<PathBuf>,
    host_override: Option<String>,
    port_override: Option<u16>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    // Load configuration
    let config_path = config_path.unwrap_or_else(|| AethericConfig::get_config_path());
    let config = AethericConfig::load_from_file(&config_path)
        .context("Failed to load configuration. Run 'aetheric config init' first.")?;

    // Use overrides or config values
    let host = host_override.unwrap_or_else(|| config.mqtt.host.clone());
    let port = port_override.unwrap_or(config.mqtt.port);

    // Validate QoS
    let qos_level = match qos {
        0 => QoS::AtMostOnce,
        1 => QoS::AtLeastOnce,
        2 => QoS::ExactlyOnce,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid QoS level: {}. Must be 0, 1, or 2",
                qos
            ))
        }
    };

    // Set up MQTT client
    let client_id = format!("aetheric-cli-sub-{}", uuid::Uuid::new_v4());
    let mut mqttoptions = MqttOptions::new(client_id, host.clone(), port);
    mqttoptions.set_keep_alive(Duration::from_secs(60));

    // Configure credentials if provided
    if let Some(username) = &config.mqtt.username {
        if let Some(password) = &config.mqtt.password {
            mqttoptions.set_credentials(username, password);
        }
    }

    // Configure TLS if enabled
    if config.mqtt.tls {
        configure_tls(&mut mqttoptions, &config)?;
    }

    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 100);

    // Subscribe to topic
    info!(
        "Subscribing to topic '{}' on {}:{} (QoS {})",
        topic, host, port, qos
    );
    client
        .subscribe(&topic, qos_level)
        .await
        .context("Failed to subscribe to topic")?;

    // Set up output writer
    let mut output_writer: Box<dyn Write + Send> = if let Some(file_path) = output_file {
        Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .with_context(|| format!("Failed to open output file: {:?}", file_path))?,
        )
    } else {
        Box::new(io::stdout())
    };

    println!("✓ Subscribed to '{}' - Press Ctrl+C to exit", topic);

    // Handle Ctrl+C gracefully
    tokio::spawn(async {
        tokio::signal::ctrl_c().await.ok();
        std::process::exit(0);
    });

    // Process incoming messages
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                info!("Connected to MQTT broker");
            }
            Ok(Event::Incoming(Packet::SubAck(_))) => {
                info!("Subscription confirmed");
            }
            Ok(Event::Incoming(Packet::Publish(publish))) => {
                let payload = String::from_utf8_lossy(&publish.payload);
                let formatted_payload = format_received_message(&payload)?;

                let output = if no_topic {
                    format!("{}\n", formatted_payload)
                } else {
                    format!("[{}] {}\n", publish.topic, formatted_payload)
                };

                output_writer
                    .write_all(output.as_bytes())
                    .context("Failed to write message to output")?;
                output_writer.flush().context("Failed to flush output")?;
            }
            Ok(_) => {
                // Other events, continue
            }
            Err(e) => {
                error!("MQTT error: {}", e);
                return Err(anyhow::anyhow!("MQTT connection error: {}", e));
            }
        }
    }
}

fn configure_tls(mqttoptions: &mut MqttOptions, _config: &AethericConfig) -> Result<()> {
    use rumqttc::TlsConfiguration;

    // Basic TLS configuration - for now just enable TLS without certificates
    // In a real implementation, you would configure the certificates properly
    let tls_config = TlsConfiguration::Simple {
        ca: vec![], // Empty CA list for now
        alpn: None,
        client_auth: None,
    };

    // TODO: Load certificates when needed
    // For now, we'll just enable basic TLS
    mqttoptions.set_transport(rumqttc::Transport::Tls(tls_config));
    Ok(())
}

fn format_message(message: &str) -> Result<String> {
    // Try to parse as JSON and pretty-print it
    if let Ok(json_value) = serde_json::from_str::<Value>(message) {
        Ok(serde_json::to_string_pretty(&json_value)?)
    } else {
        // Not JSON, return as-is
        Ok(message.to_string())
    }
}

fn format_received_message(message: &str) -> Result<String> {
    // Try to parse as JSON and pretty-print it for better readability
    if let Ok(json_value) = serde_json::from_str::<Value>(message) {
        Ok(serde_json::to_string(&json_value)?) // Compact JSON for received messages
    } else {
        // Not JSON, return as-is
        Ok(message.to_string())
    }
}
