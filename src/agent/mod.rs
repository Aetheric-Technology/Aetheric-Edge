use crate::config::AethericConfig;
use crate::mqtt::{messages::*, MqttClient};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub mod command_handler;
pub mod health_monitor;
pub mod plugin_manager;
pub mod ssh_tunnel;

pub use command_handler::CommandHandler;
pub use health_monitor::HealthMonitor;
pub use ssh_tunnel::SshTunnelManager;

pub struct Agent {
    #[allow(dead_code)]
    config: Arc<AethericConfig>,
    mqtt_client: MqttClient,
    command_handler: CommandHandler,
    health_monitor: HealthMonitor,
    ssh_tunnel_manager: Arc<SshTunnelManager>,
    command_receiver: mpsc::UnboundedReceiver<CommandMessage>,
}

impl Agent {
    pub fn new(
        config: AethericConfig,
        mqtt_client: MqttClient,
        command_receiver: mpsc::UnboundedReceiver<CommandMessage>,
    ) -> Self {
        let config = Arc::new(config);
        let mqtt_client_arc = Arc::new(mqtt_client.clone());
        let ssh_tunnel_manager = Arc::new(SshTunnelManager::new(config.clone(), mqtt_client_arc));
        let command_handler = CommandHandler::new(config.clone(), ssh_tunnel_manager.clone());
        let health_monitor = HealthMonitor::new(config.clone());

        Self {
            config,
            mqtt_client,
            command_handler,
            health_monitor,
            ssh_tunnel_manager: ssh_tunnel_manager.clone(),
            command_receiver,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting Aetheric Edge Agent");

        // Publish online status
        if let Err(e) = self.mqtt_client.publish_online_status(&self.config.gateway.id).await {
            error!("Failed to publish online status: {}", e);
        }

        // Send startup event
        if let Err(e) = self.health_monitor.send_startup_event(&self.mqtt_client).await {
            error!("Failed to send startup event: {}", e);
        }

        // Start SSH tunnel manager
        if let Err(e) = self.ssh_tunnel_manager.start().await {
            error!("Failed to start SSH tunnel manager: {}", e);
        }

        // Start health monitoring
        let health_mqtt_client = self.mqtt_client.clone();
        let mut health_monitor = self.health_monitor.clone();
        let health_handle = tokio::spawn(async move {
            if let Err(e) = health_monitor.run(health_mqtt_client).await {
                error!("Health monitor error: {}", e);
            }
        });

        // Main command processing loop
        let command_loop_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(command) = self.command_receiver.recv() => {
                        self.handle_command(command).await;
                    }
                    else => {
                        warn!("Command receiver closed, shutting down");
                        break;
                    }
                }
            }
        });

        // Wait for tasks to complete
        tokio::try_join!(health_handle, command_loop_handle).context("Agent task failed")?;

        Ok(())
    }

    async fn handle_command(&self, command: CommandMessage) {
        info!("Processing command: {:?}", command.command);

        // Send immediate acknowledgment
        let ack_response = CommandResponse::new(
            command.id.clone(),
            CommandStatus::Received,
            "Command received and queued for processing".to_string(),
        );

        if let Err(e) = self
            .mqtt_client
            .publish_command_response(&ack_response)
            .await
        {
            error!("Failed to send command acknowledgment: {}", e);
        }

        // Process the command
        let response = self.command_handler.handle_command(command).await;

        // Send final response
        if let Err(e) = self.mqtt_client.publish_command_response(&response).await {
            error!("Failed to send command response: {}", e);
        }
    }
}
