use crate::mqtt::{messages::*, topics::*};
use anyhow::{Context, Result};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct MqttClient {
    client: AsyncClient,
    topic_builder: TopicBuilder,
    command_sender: mpsc::UnboundedSender<CommandMessage>,
}

impl MqttClient {
    pub async fn new(
        broker_host: String,
        broker_port: u16,
        gateway_id: String,
        command_sender: mpsc::UnboundedSender<CommandMessage>,
    ) -> Result<(Self, EventLoop)> {
        let mut mqtt_options = MqttOptions::new(&gateway_id, broker_host, broker_port);
        mqtt_options.set_keep_alive(Duration::from_secs(30));
        mqtt_options.set_clean_session(false);
        mqtt_options.set_max_packet_size(1024 * 1024, 1024 * 1024); // 1MB

        let (client, event_loop) = AsyncClient::new(mqtt_options, 100);
        let topic_builder = TopicBuilder::new(gateway_id);

        Ok((
            Self {
                client,
                topic_builder,
                command_sender,
            },
            event_loop,
        ))
    }

    pub async fn new_with_config(
        config: &crate::config::MqttConfig,
        gateway_id: String,
        command_sender: mpsc::UnboundedSender<CommandMessage>,
    ) -> Result<(Self, EventLoop)> {
        let mut mqtt_options = MqttOptions::new(&gateway_id, &config.host, config.port);
        mqtt_options.set_keep_alive(Duration::from_secs(30));
        mqtt_options.set_clean_session(false);
        mqtt_options.set_max_packet_size(1024 * 1024, 1024 * 1024); // 1MB

        // Set credentials if provided
        if let Some(username) = &config.username {
            if let Some(password) = &config.password {
                mqtt_options.set_credentials(username, password);
            }
        }

        // Set Last Will Testament (LWT) for offline detection
        let will_topic = format!("ae/{}/status", gateway_id);
        let will_payload = serde_json::json!({
            "gateway_id": &gateway_id,
            "status": "offline",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "reason": "connection_lost"
        }).to_string();
        
        mqtt_options.set_last_will(rumqttc::LastWill::new(
            will_topic,
            will_payload.into_bytes(),
            QoS::AtLeastOnce,
            true, // Retain flag
        ));

        let (client, event_loop) = AsyncClient::new(mqtt_options, 100);
        let topic_builder = TopicBuilder::new(gateway_id.clone());

        // Publish online status immediately after connection
        let mqtt_client = Self {
            client,
            topic_builder,
            command_sender,
        };

        Ok((mqtt_client, event_loop))
    }

    pub async fn subscribe_to_commands(&self) -> Result<()> {
        let commands_topic = self.topic_builder.commands();
        info!("Subscribing to commands topic: {}", commands_topic);

        self.client
            .subscribe(&commands_topic, QoS::AtLeastOnce)
            .await
            .context("Failed to subscribe to commands topic")?;

        Ok(())
    }

    pub async fn publish_health(&self, health: &HealthMessage) -> Result<()> {
        let topic = self.topic_builder.health();
        let payload = serde_json::to_vec(health).context("Failed to serialize health message")?;

        debug!("Publishing health status to topic: {}", topic);
        self.client
            .publish(&topic, QoS::AtLeastOnce, false, payload)
            .await
            .context("Failed to publish health message")?;

        Ok(())
    }

    pub async fn publish_command_response(&self, response: &CommandResponse) -> Result<()> {
        let topic = self.topic_builder.command_response(&response.command_id);
        let payload =
            serde_json::to_vec(response).context("Failed to serialize command response")?;

        debug!("Publishing command response to topic: {}", topic);
        self.client
            .publish(&topic, QoS::AtLeastOnce, false, payload)
            .await
            .context("Failed to publish command response")?;

        Ok(())
    }

    pub async fn publish_event(&self, event: &EventMessage) -> Result<()> {
        let topic = self.topic_builder.events();
        let payload = serde_json::to_vec(event).context("Failed to serialize event message")?;

        debug!("Publishing event to topic: {}", topic);
        self.client
            .publish(&topic, QoS::AtLeastOnce, false, payload)
            .await
            .context("Failed to publish event message")?;

        Ok(())
    }

    pub async fn publish_telemetry(&self, telemetry: &TelemetryMessage) -> Result<()> {
        let topic = self.topic_builder.telemetry();
        let payload =
            serde_json::to_vec(telemetry).context("Failed to serialize telemetry message")?;

        debug!("Publishing telemetry to topic: {}", topic);
        self.client
            .publish(&topic, QoS::AtMostOnce, false, payload)
            .await
            .context("Failed to publish telemetry message")?;

        Ok(())
    }

    pub async fn publish_ota_status(&self, status: &OtaStatus) -> Result<()> {
        let topic = self.topic_builder.ota_status();
        let payload = serde_json::to_vec(status).context("Failed to serialize OTA status")?;

        info!("Publishing OTA status to topic: {}", topic);
        self.client
            .publish(&topic, QoS::AtLeastOnce, false, payload)
            .await
            .context("Failed to publish OTA status")?;

        Ok(())
    }

    pub async fn handle_mqtt_event(&self, event: Event) -> Result<()> {
        match event {
            Event::Incoming(Packet::Publish(publish)) => {
                self.handle_publish(publish).await?;
            }
            Event::Incoming(Packet::ConnAck(_)) => {
                info!("Connected to MQTT broker");
                self.subscribe_to_commands().await?;
            }
            Event::Incoming(Packet::SubAck(_)) => {
                debug!("Successfully subscribed to topic");
            }
            Event::Incoming(packet) => {
                debug!("Received MQTT packet: {:?}", packet);
            }
            Event::Outgoing(_) => {
                // Debug outgoing packets if needed
            }
        }
        Ok(())
    }

    async fn handle_publish(&self, publish: rumqttc::Publish) -> Result<()> {
        let topic = &publish.topic;
        let payload = &publish.payload;

        debug!("Received message on topic: {}", topic);

        if let Some(_command_id) = parse_command_topic(topic, self.topic_builder.gateway_id()) {
            match serde_json::from_slice::<CommandMessage>(payload) {
                Ok(command) => {
                    info!("Received command: {:?}", command.command);
                    if let Err(e) = self.command_sender.send(command) {
                        error!("Failed to send command to handler: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to parse command message: {}", e);
                }
            }
        } else {
            warn!("Received message on unexpected topic: {}", topic);
        }

        Ok(())
    }

    pub fn topic_builder(&self) -> &TopicBuilder {
        &self.topic_builder
    }

    pub async fn publish_raw(&self, topic: &str, payload: &str) -> Result<()> {
        debug!("Publishing raw message to topic: {}", topic);
        self.client
            .publish(topic, QoS::AtLeastOnce, false, payload.as_bytes())
            .await
            .context("Failed to publish raw message")?;
        Ok(())
    }

    pub async fn subscribe_raw(&self, topic: &str) -> Result<()> {
        debug!("Subscribing to raw topic: {}", topic);
        self.client
            .subscribe(topic, QoS::AtLeastOnce)
            .await
            .context("Failed to subscribe to raw topic")?;
        Ok(())
    }

    pub async fn publish_online_status(&self, gateway_id: &str) -> Result<()> {
        let status_topic = format!("ae/{}/status", gateway_id);
        let status_payload = serde_json::json!({
            "gateway_id": gateway_id,
            "status": "online",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "reason": "connected"
        }).to_string();
        
        debug!("Publishing online status to topic: {}", status_topic);
        self.client
            .publish(&status_topic, QoS::AtLeastOnce, true, status_payload.as_bytes())
            .await
            .context("Failed to publish online status")?;

        info!("Published online status with retain flag");
        Ok(())
    }
}

pub async fn run_mqtt_event_loop(mut event_loop: EventLoop, mqtt_client: MqttClient) -> Result<()> {
    info!("Starting MQTT event loop");

    loop {
        match event_loop.poll().await {
            Ok(event) => {
                if let Err(e) = mqtt_client.handle_mqtt_event(event).await {
                    error!("Error handling MQTT event: {}", e);
                }
            }
            Err(e) => {
                error!("MQTT connection error: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
