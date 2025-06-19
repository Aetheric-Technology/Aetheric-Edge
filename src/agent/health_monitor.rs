use crate::agent::plugin_manager::PluginManager;
use crate::config::AethericConfig;
use crate::mqtt::{messages::*, MqttClient};
use anyhow::Result;
use std::sync::Arc;
use std::time::SystemTime;
use sysinfo::{System, SystemExt, CpuExt};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct HealthMonitor {
    config: Arc<AethericConfig>,
    start_time: SystemTime,
    plugin_manager: PluginManager,
}

impl HealthMonitor {
    pub fn new(config: Arc<AethericConfig>) -> Self {
        let plugin_manager = PluginManager::new(config.clone());
        Self {
            config,
            start_time: SystemTime::now(),
            plugin_manager,
        }
    }

    pub async fn run(&mut self, mqtt_client: MqttClient) -> Result<()> {
        info!("Starting comprehensive health monitor");

        let mut health_interval = interval(Duration::from_secs(self.config.health.report_interval_seconds));
        let mut heartbeat_interval = interval(Duration::from_secs(15)); // Heartbeat every 15 seconds
        let mut plugin_health_interval = interval(Duration::from_secs(60)); // Plugin health check every minute

        loop {
            tokio::select! {
                _ = health_interval.tick() => {
                    if let Err(e) = self.report_health(&mqtt_client).await {
                        error!("Failed to report health: {}", e);
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if let Err(e) = self.send_heartbeat(&mqtt_client).await {
                        error!("Failed to send heartbeat: {}", e);
                    }
                }
                _ = plugin_health_interval.tick() => {
                    if let Err(e) = self.monitor_plugin_health(&mqtt_client).await {
                        error!("Failed to monitor plugin health: {}", e);
                    }
                }
            }
        }
    }

    async fn report_health(&self, mqtt_client: &MqttClient) -> Result<()> {
        debug!("Collecting health metrics");

        let health_message = HealthMessage {
            status: self.get_health_status().await,
            timestamp: chrono::Utc::now().to_rfc3339(),
            gateway_id: self.config.gateway.id.clone(),
            uptime_seconds: self.get_uptime_seconds(),
            memory_usage_mb: self.get_memory_usage_mb().await,
            cpu_usage_percent: self.get_cpu_usage_percent().await,
        };

        mqtt_client.publish_health(&health_message).await?;
        debug!("Health status reported successfully");

        Ok(())
    }

    async fn get_health_status(&self) -> HealthStatus {
        // Check various system health indicators
        let memory_usage = self.get_memory_usage_mb().await;
        let cpu_usage = self.get_cpu_usage_percent().await;
        
        // Simple health determination logic
        if memory_usage > 8192 || cpu_usage > 90.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        }
    }

    fn get_uptime_seconds(&self) -> u64 {
        self.start_time
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    async fn get_memory_usage_mb(&self) -> u64 {
        let mut system = System::new_all();
        system.refresh_memory();
        
        let used_memory = system.used_memory();
        used_memory / 1024 / 1024 // Convert bytes to MB
    }

    async fn get_cpu_usage_percent(&self) -> f32 {
        let mut system = System::new_all();
        system.refresh_cpu(); // Refresh once
        
        // Wait a bit for accurate measurement
        tokio::time::sleep(Duration::from_millis(200)).await;
        system.refresh_cpu(); // Refresh again for delta calculation
        
        // Get global CPU usage
        system.global_cpu_info().cpu_usage()
    }

    pub async fn send_startup_event(&self, mqtt_client: &MqttClient) -> Result<()> {
        let event = EventMessage::new(
            "system".to_string(),
            "Aetheric Edge Agent started".to_string(),
            EventSeverity::Info,
        )
        .with_metadata("gateway_id".to_string(), serde_json::json!(self.config.gateway.id))
        .with_metadata("version".to_string(), serde_json::json!(env!("CARGO_PKG_VERSION")));

        mqtt_client.publish_event(&event).await?;
        info!("Startup event published");

        Ok(())
    }

    pub async fn send_shutdown_event(&self, mqtt_client: &MqttClient) -> Result<()> {
        let event = EventMessage::new(
            "system".to_string(),
            "Aetheric Edge Agent shutting down".to_string(),
            EventSeverity::Info,
        )
        .with_metadata("gateway_id".to_string(), serde_json::json!(self.config.gateway.id))
        .with_metadata("uptime_seconds".to_string(), serde_json::json!(self.get_uptime_seconds()));

        mqtt_client.publish_event(&event).await?;
        info!("Shutdown event published");

        Ok(())
    }

    async fn send_heartbeat(&self, mqtt_client: &MqttClient) -> Result<()> {
        debug!("Sending heartbeat");

        let heartbeat_message = serde_json::json!({
            "gateway_id": self.config.gateway.id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "uptime_seconds": self.get_uptime_seconds(),
            "status": "alive",
            "type": "heartbeat"
        });

        // Publish to heartbeat topic
        let topic = format!("ae/{}/heartbeat", self.config.gateway.id);
        mqtt_client.publish_raw(&topic, &heartbeat_message.to_string()).await?;
        
        debug!("Heartbeat sent successfully");
        Ok(())
    }

    async fn monitor_plugin_health(&self, mqtt_client: &MqttClient) -> Result<()> {
        debug!("Monitoring plugin health");

        match self.plugin_manager.monitor_all_plugins_health().await {
            Ok(plugin_health_statuses) => {
                // Publish plugin health status
                let plugin_health_message = serde_json::json!({
                    "gateway_id": self.config.gateway.id,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "plugins": plugin_health_statuses,
                    "total_plugins": plugin_health_statuses.len(),
                    "unhealthy_plugins": plugin_health_statuses.iter()
                        .filter(|p| !matches!(p.status, crate::agent::plugin_manager::PluginStatus::Running))
                        .count()
                });

                let topic = format!("ae/{}/plugins/health", self.config.gateway.id);
                mqtt_client.publish_raw(&topic, &plugin_health_message.to_string()).await?;

                // Report any critical plugin issues
                for plugin_health in &plugin_health_statuses {
                    if matches!(plugin_health.status, crate::agent::plugin_manager::PluginStatus::Failed) {
                        let alert_message = EventMessage::new(
                            "plugin_health".to_string(),
                            format!("Plugin {} has failed and exceeded maximum restart attempts", plugin_health.plugin_name),
                            EventSeverity::Critical,
                        )
                        .with_metadata("plugin_name".to_string(), serde_json::json!(plugin_health.plugin_name))
                        .with_metadata("restart_count".to_string(), serde_json::json!(plugin_health.restart_count))
                        .with_metadata("health_failures".to_string(), serde_json::json!(plugin_health.health_check_failures));

                        if let Err(e) = mqtt_client.publish_event(&alert_message).await {
                            warn!("Failed to publish plugin health alert: {}", e);
                        }
                    } else if plugin_health.restart_count > 0 {
                        let warning_message = EventMessage::new(
                            "plugin_health".to_string(),
                            format!("Plugin {} has been restarted {} times", plugin_health.plugin_name, plugin_health.restart_count),
                            EventSeverity::Warning,
                        )
                        .with_metadata("plugin_name".to_string(), serde_json::json!(plugin_health.plugin_name))
                        .with_metadata("restart_count".to_string(), serde_json::json!(plugin_health.restart_count))
                        .with_metadata("status".to_string(), serde_json::json!(plugin_health.status));

                        if let Err(e) = mqtt_client.publish_event(&warning_message).await {
                            warn!("Failed to publish plugin restart warning: {}", e);
                        }
                    }
                }

                debug!("Plugin health monitoring completed - {} plugins checked", plugin_health_statuses.len());
            }
            Err(e) => {
                error!("Failed to monitor plugin health: {}", e);
                
                let error_message = EventMessage::new(
                    "plugin_health".to_string(),
                    format!("Plugin health monitoring failed: {}", e),
                    EventSeverity::Error,
                );

                if let Err(e) = mqtt_client.publish_event(&error_message).await {
                    warn!("Failed to publish plugin health monitoring error: {}", e);
                }
            }
        }

        Ok(())
    }
}