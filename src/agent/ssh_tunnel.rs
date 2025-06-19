use crate::config::AethericConfig;
use crate::mqtt::client::MqttClient;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    pub session_id: String,
    pub client_id: String,
    pub created_at: u64,
    pub last_activity: u64,
    pub status: SshSessionStatus,
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SshSessionStatus {
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshCommand {
    Connect {
        session_id: String,
        target_host: Option<String>,
        target_port: Option<u16>,
        duration_minutes: Option<u32>,
    },
    Disconnect {
        session_id: String,
    },
    Data {
        session_id: String,
        data: String, // base64 encoded data
        direction: SshDataDirection,
    },
    Heartbeat {
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshDataDirection {
    Up,   // Client to server (upstream)
    Down, // Server to client (downstream)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshResponse {
    pub session_id: String,
    pub status: SshSessionStatus,
    pub message: String,
    pub data: Option<String>, // base64 encoded data for data responses
    pub local_port: Option<u16>,
}

struct ActiveSession {
    session: SshSession,
    upstream_tx: mpsc::UnboundedSender<Vec<u8>>,
    #[allow(dead_code)]
    downstream_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    _handle: tokio::task::JoinHandle<()>,
}

pub struct SshTunnelManager {
    config: Arc<AethericConfig>,
    mqtt_client: Arc<MqttClient>,
    sessions: Arc<RwLock<HashMap<String, ActiveSession>>>,
    gateway_id: String,
}

impl SshTunnelManager {
    pub fn new(config: Arc<AethericConfig>, mqtt_client: Arc<MqttClient>) -> Self {
        Self {
            gateway_id: config.gateway.id.clone(),
            config,
            mqtt_client,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting SSH tunnel manager");

        if !self.config.ssh.enabled {
            warn!("SSH functionality is disabled in configuration");
            return Ok(());
        }

        // Subscribe to SSH-related MQTT topics
        self.subscribe_to_ssh_topics().await?;

        // Start session cleanup task
        self.start_session_cleanup_task().await;

        info!("SSH tunnel manager started successfully");
        Ok(())
    }

    async fn subscribe_to_ssh_topics(&self) -> Result<()> {
        let topics = vec![
            format!("ae/{}/ssh/+/connect", self.gateway_id),
            format!("ae/{}/ssh/+/disconnect", self.gateway_id),
            format!("ae/{}/ssh/+/data/up", self.gateway_id),
            format!("ae/{}/ssh/+/heartbeat", self.gateway_id),
        ];

        for topic in topics {
            self.mqtt_client.subscribe_raw(&topic).await?;
            debug!("Subscribed to SSH topic: {}", topic);
        }

        Ok(())
    }

    pub async fn handle_ssh_command(&self, command: SshCommand) -> Result<SshResponse> {
        match command {
            SshCommand::Connect {
                session_id,
                target_host,
                target_port,
                duration_minutes,
            } => {
                self.handle_connect_command(session_id, target_host, target_port, duration_minutes)
                    .await
            }
            SshCommand::Disconnect { session_id } => {
                self.handle_disconnect_command(session_id).await
            }
            SshCommand::Data {
                session_id,
                data,
                direction,
            } => self.handle_data_command(session_id, data, direction).await,
            SshCommand::Heartbeat { session_id } => self.handle_heartbeat_command(session_id).await,
        }
    }

    async fn handle_connect_command(
        &self,
        session_id: String,
        target_host: Option<String>,
        target_port: Option<u16>,
        duration_minutes: Option<u32>,
    ) -> Result<SshResponse> {
        info!("Handling SSH connect command for session: {}", session_id);

        // Check if session already exists
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&session_id) {
                return Ok(SshResponse {
                    session_id: session_id.clone(),
                    status: SshSessionStatus::Failed,
                    message: "Session already exists".to_string(),
                    data: None,
                    local_port: None,
                });
            }
        }

        // Check session limits
        {
            let sessions = self.sessions.read().await;
            if sessions.len() >= self.config.ssh.max_sessions as usize {
                return Ok(SshResponse {
                    session_id: session_id.clone(),
                    status: SshSessionStatus::Failed,
                    message: "Maximum number of SSH sessions reached".to_string(),
                    data: None,
                    local_port: None,
                });
            }
        }

        let target_host = target_host.unwrap_or_else(|| "127.0.0.1".to_string());
        let target_port = target_port.unwrap_or(22);

        // Create the SSH tunnel
        match self
            .create_ssh_tunnel(
                session_id.clone(),
                target_host.clone(),
                target_port,
                duration_minutes,
            )
            .await
        {
            Ok(local_port) => {
                info!(
                    "SSH tunnel created successfully for session {} on port {}",
                    session_id, local_port
                );
                Ok(SshResponse {
                    session_id,
                    status: SshSessionStatus::Connected,
                    message: "SSH tunnel established".to_string(),
                    data: None,
                    local_port: Some(local_port),
                })
            }
            Err(e) => {
                error!(
                    "Failed to create SSH tunnel for session {}: {}",
                    session_id, e
                );
                Ok(SshResponse {
                    session_id,
                    status: SshSessionStatus::Failed,
                    message: format!("Failed to create tunnel: {}", e),
                    data: None,
                    local_port: None,
                })
            }
        }
    }

    async fn create_ssh_tunnel(
        &self,
        session_id: String,
        target_host: String,
        target_port: u16,
        duration_minutes: Option<u32>,
    ) -> Result<u16> {
        // Find available local port
        let local_port = self.find_available_port().await?;

        // Create local TCP listener
        let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;
        info!("SSH tunnel listening on 127.0.0.1:{}", local_port);

        // Create channels for data communication
        let (upstream_tx, _upstream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (downstream_tx, downstream_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Create session
        let session = SshSession {
            session_id: session_id.clone(),
            client_id: "mqtt-tunnel".to_string(),
            created_at: now,
            last_activity: now,
            status: SshSessionStatus::Connecting,
            local_port,
            target_host: target_host.clone(),
            target_port,
        };

        // Clone necessary data for the tunnel task
        let session_id_clone = session_id.clone();
        let mqtt_client = self.mqtt_client.clone();
        let gateway_id = self.gateway_id.clone();
        let sessions = self.sessions.clone();
        let config = self.config.clone();

        // Clone upstream_tx before moving it to the async task
        let upstream_tx_for_spawn = upstream_tx.clone();

        // Start the tunnel handling task
        let handle = tokio::spawn(async move {
            if let Err(e) = Self::handle_tunnel_connections(
                listener,
                session_id_clone.clone(),
                target_host,
                target_port,
                upstream_tx_for_spawn,
                downstream_tx,
                mqtt_client,
                gateway_id,
                duration_minutes,
                config,
            )
            .await
            {
                error!(
                    "Tunnel handling failed for session {}: {}",
                    session_id_clone, e
                );

                // Remove session on failure
                let mut sessions_guard = sessions.write().await;
                sessions_guard.remove(&session_id_clone);
            }
        });

        // Store active session
        let active_session = ActiveSession {
            session,
            upstream_tx,
            downstream_rx,
            _handle: handle,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id, active_session);
        }

        Ok(local_port)
    }

    async fn handle_tunnel_connections(
        listener: TcpListener,
        session_id: String,
        target_host: String,
        target_port: u16,
        upstream_tx: mpsc::UnboundedSender<Vec<u8>>,
        downstream_tx: mpsc::UnboundedSender<Vec<u8>>,
        mqtt_client: Arc<MqttClient>,
        gateway_id: String,
        duration_minutes: Option<u32>,
        config: Arc<AethericConfig>,
    ) -> Result<()> {
        info!(
            "Starting tunnel connection handler for session: {}",
            session_id
        );

        // Set session timeout
        let session_timeout =
            duration_minutes.unwrap_or(config.ssh.session_timeout_minutes) as u64 * 60;

        let session_start = SystemTime::now();

        // Accept incoming connections
        while let Ok((local_stream, addr)) = listener.accept().await {
            info!(
                "New SSH tunnel connection from: {} for session: {}",
                addr, session_id
            );

            // Check session timeout
            if let Ok(elapsed) = session_start.elapsed() {
                if elapsed.as_secs() > session_timeout {
                    warn!("Session {} timed out", session_id);
                    break;
                }
            }

            // Connect to target SSH server
            match TcpStream::connect(format!("{}:{}", target_host, target_port)).await {
                Ok(target_stream) => {
                    info!(
                        "Connected to SSH server {}:{} for session {}",
                        target_host, target_port, session_id
                    );

                    // Clone necessary data for the connection handler
                    let session_id_clone = session_id.clone();
                    let upstream_tx_clone = upstream_tx.clone();
                    let downstream_tx_clone = downstream_tx.clone();
                    let mqtt_client_clone = mqtt_client.clone();
                    let gateway_id_clone = gateway_id.clone();

                    // Handle the connection in a separate task
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection_streams(
                            local_stream,
                            target_stream,
                            session_id_clone,
                            upstream_tx_clone,
                            downstream_tx_clone,
                            mqtt_client_clone,
                            gateway_id_clone,
                        )
                        .await
                        {
                            error!("Connection handling failed: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!(
                        "Failed to connect to SSH server {}:{}: {}",
                        target_host, target_port, e
                    );
                    // Send error response via MQTT
                    let error_topic = format!("ae/{}/ssh/{}/error", gateway_id, session_id);
                    let error_message = serde_json::json!({
                        "session_id": session_id,
                        "error": format!("Failed to connect to SSH server: {}", e)
                    });
                    let _ = mqtt_client
                        .publish_raw(&error_topic, &error_message.to_string())
                        .await;
                }
            }
        }

        info!(
            "Tunnel connection handler stopped for session: {}",
            session_id
        );
        Ok(())
    }

    async fn handle_connection_streams(
        local_stream: TcpStream,
        target_stream: TcpStream,
        session_id: String,
        _upstream_tx: mpsc::UnboundedSender<Vec<u8>>,
        _downstream_tx: mpsc::UnboundedSender<Vec<u8>>,
        mqtt_client: Arc<MqttClient>,
        gateway_id: String,
    ) -> Result<()> {
        let (mut local_read, mut local_write) = local_stream.into_split();
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Handle local to target (upstream) data flow
        let upstream_session_id = session_id.clone();
        let upstream_mqtt = mqtt_client.clone();
        let upstream_gateway = gateway_id.clone();
        let upstream_handle = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                match local_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data = buffer[..n].to_vec();

                        // Send data via MQTT
                        let topic = format!(
                            "ae/{}/ssh/{}/data/up",
                            upstream_gateway, upstream_session_id
                        );
                        let data_b64 = general_purpose::STANDARD.encode(&data);
                        let message = serde_json::json!({
                            "session_id": upstream_session_id,
                            "data": data_b64,
                            "direction": "up"
                        });

                        if let Err(e) = upstream_mqtt
                            .publish_raw(&topic, &message.to_string())
                            .await
                        {
                            error!("Failed to publish upstream data: {}", e);
                            break;
                        }

                        // Also forward directly to target
                        if let Err(e) = target_write.write_all(&data).await {
                            error!("Failed to write to target stream: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from local stream: {}", e);
                        break;
                    }
                }
            }
        });

        // Handle target to local (downstream) data flow
        let downstream_session_id = session_id.clone();
        let downstream_mqtt = mqtt_client.clone();
        let downstream_gateway = gateway_id.clone();
        let downstream_handle = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                match target_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data = buffer[..n].to_vec();

                        // Send data via MQTT
                        let topic = format!(
                            "ae/{}/ssh/{}/data/down",
                            downstream_gateway, downstream_session_id
                        );
                        let data_b64 = general_purpose::STANDARD.encode(&data);
                        let message = serde_json::json!({
                            "session_id": downstream_session_id,
                            "data": data_b64,
                            "direction": "down"
                        });

                        if let Err(e) = downstream_mqtt
                            .publish_raw(&topic, &message.to_string())
                            .await
                        {
                            error!("Failed to publish downstream data: {}", e);
                            break;
                        }

                        // Also forward directly to local client
                        if let Err(e) = local_write.write_all(&data).await {
                            error!("Error writing to local stream: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from target stream: {}", e);
                        break;
                    }
                }
            }
        });

        // Wait for either task to complete
        tokio::select! {
            _ = upstream_handle => {
                debug!("Upstream handler completed for session {}", session_id);
            }
            _ = downstream_handle => {
                debug!("Downstream handler completed for session {}", session_id);
            }
        }

        info!(
            "Connection streams handler completed for session: {}",
            session_id
        );
        Ok(())
    }

    async fn handle_disconnect_command(&self, session_id: String) -> Result<SshResponse> {
        info!(
            "Handling SSH disconnect command for session: {}",
            session_id
        );

        {
            let mut sessions = self.sessions.write().await;
            if let Some(_session) = sessions.remove(&session_id) {
                info!("SSH session {} disconnected successfully", session_id);
                Ok(SshResponse {
                    session_id,
                    status: SshSessionStatus::Disconnected,
                    message: "Session disconnected".to_string(),
                    data: None,
                    local_port: None,
                })
            } else {
                warn!(
                    "Attempted to disconnect non-existent session: {}",
                    session_id
                );
                Ok(SshResponse {
                    session_id,
                    status: SshSessionStatus::Failed,
                    message: "Session not found".to_string(),
                    data: None,
                    local_port: None,
                })
            }
        }
    }

    async fn handle_data_command(
        &self,
        session_id: String,
        data: String,
        direction: SshDataDirection,
    ) -> Result<SshResponse> {
        debug!(
            "Handling SSH data command for session: {} direction: {:?}",
            session_id, direction
        );

        let sessions = self.sessions.read().await;
        if let Some(active_session) = sessions.get(&session_id) {
            // Decode base64 data
            let decoded_data = general_purpose::STANDARD
                .decode(&data)
                .map_err(|e| anyhow!("Failed to decode base64 data: {}", e))?;

            match direction {
                SshDataDirection::Up => {
                    // Send data upstream (client to server)
                    if let Err(e) = active_session.upstream_tx.send(decoded_data) {
                        error!(
                            "Failed to send upstream data for session {}: {}",
                            session_id, e
                        );
                        return Ok(SshResponse {
                            session_id,
                            status: SshSessionStatus::Failed,
                            message: "Failed to send data upstream".to_string(),
                            data: None,
                            local_port: None,
                        });
                    }
                }
                SshDataDirection::Down => {
                    // Data coming downstream is handled by the connection streams
                    // This case might be used for external MQTT-only clients
                    debug!("Received downstream data for session {}", session_id);
                }
            }

            Ok(SshResponse {
                session_id,
                status: SshSessionStatus::Connected,
                message: "Data forwarded".to_string(),
                data: None,
                local_port: None,
            })
        } else {
            warn!("Data command for non-existent session: {}", session_id);
            Ok(SshResponse {
                session_id,
                status: SshSessionStatus::Failed,
                message: "Session not found".to_string(),
                data: None,
                local_port: None,
            })
        }
    }

    async fn handle_heartbeat_command(&self, session_id: String) -> Result<SshResponse> {
        debug!("Handling SSH heartbeat for session: {}", session_id);

        let mut sessions = self.sessions.write().await;
        if let Some(active_session) = sessions.get_mut(&session_id) {
            // Update last activity timestamp
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            active_session.session.last_activity = now;

            Ok(SshResponse {
                session_id,
                status: SshSessionStatus::Connected,
                message: "Heartbeat received".to_string(),
                data: None,
                local_port: Some(active_session.session.local_port),
            })
        } else {
            Ok(SshResponse {
                session_id,
                status: SshSessionStatus::Failed,
                message: "Session not found".to_string(),
                data: None,
                local_port: None,
            })
        }
    }

    async fn find_available_port(&self) -> Result<u16> {
        for port in 10000..11000 {
            if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                drop(listener);
                return Ok(port);
            }
        }
        Err(anyhow!("No available ports found in range 10000-11000"))
    }

    async fn start_session_cleanup_task(&self) {
        let sessions = self.sessions.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Check every minute

            loop {
                interval.tick().await;

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let timeout_threshold = config.ssh.session_timeout_minutes as u64 * 60;

                let mut sessions_guard = sessions.write().await;
                let mut sessions_to_remove = Vec::new();

                for (session_id, active_session) in sessions_guard.iter() {
                    let inactive_duration =
                        now.saturating_sub(active_session.session.last_activity);

                    if inactive_duration > timeout_threshold {
                        info!(
                            "SSH session {} timed out (inactive for {} seconds)",
                            session_id, inactive_duration
                        );
                        sessions_to_remove.push(session_id.clone());
                    }
                }

                for session_id in sessions_to_remove {
                    sessions_guard.remove(&session_id);
                    info!("Removed timed out SSH session: {}", session_id);
                }
            }
        });
    }

    pub async fn get_active_sessions(&self) -> Result<Vec<SshSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().map(|s| s.session.clone()).collect())
    }

    pub async fn get_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }
}
