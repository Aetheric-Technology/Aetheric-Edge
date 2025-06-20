use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{error, info};

#[cfg(windows)]
use tokio::signal;

mod agent;
mod certs;
mod config;
mod mqtt;

use agent::Agent;
use config::AethericConfig;
use mqtt::{run_mqtt_event_loop, MqttClient};

#[derive(Parser)]
#[command(name = "aetheric-agent")]
#[command(about = "Aetheric Edge Agent - MQTT-based edge computing agent")]
#[command(version)]
struct Args {
    #[arg(short, long, help = "Path to configuration file")]
    config: Option<PathBuf>,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,

    #[arg(long, help = "Generate default configuration file")]
    generate_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_filter = if args.verbose {
        "debug,rumqttc=info"
    } else {
        "info,rumqttc=warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_target(false)
        .init();

    info!(
        "Starting Aetheric Edge Agent v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Determine config file path
    let config_path = args
        .config
        .unwrap_or_else(AethericConfig::get_config_path);

    // Handle config generation
    if args.generate_config {
        let default_config = AethericConfig::default();
        default_config
            .save_to_file(&config_path)
            .context("Failed to generate default configuration")?;
        info!("Default configuration saved to: {:?}", config_path);
        return Ok(());
    }

    // Load configuration
    let config =
        AethericConfig::load_from_file(&config_path).context("Failed to load configuration")?;

    info!("Configuration loaded from: {:?}", config_path);
    info!("Gateway ID: {}", config.gateway.id);
    info!("MQTT Broker: {}:{}", config.mqtt.host, config.mqtt.port);

    // Create command channel
    let (command_sender, command_receiver) = mpsc::unbounded_channel();

    // Create MQTT client
    let (mqtt_client, event_loop) = MqttClient::new(
        config.mqtt.host.clone(),
        config.mqtt.port,
        config.gateway.id.clone(),
        command_sender,
    )
    .await
    .context("Failed to create MQTT client")?;

    // Create and start the agent
    let agent = Agent::new(config, mqtt_client.clone(), command_receiver);

    // Start MQTT event loop
    let mqtt_handle = tokio::spawn(run_mqtt_event_loop(event_loop, mqtt_client.clone()));

    // Start the agent
    let agent_handle = tokio::spawn(async move {
        if let Err(e) = agent.run().await {
            error!("Agent error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            info!("Received shutdown signal");
        }
        result = mqtt_handle => {
            if let Err(e) = result {
                error!("MQTT event loop error: {}", e);
            }
        }
        result = agent_handle => {
            if let Err(e) = result {
                error!("Agent task error: {}", e);
            }
        }
    }

    info!("Shutting down Aetheric Edge Agent");
    Ok(())
}

/// Cross-platform shutdown signal handling
async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }
    }

    #[cfg(windows)]
    {
        signal::ctrl_c().await?;
        info!("Received Ctrl+C");
    }

    Ok(())
}
