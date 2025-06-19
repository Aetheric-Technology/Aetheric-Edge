#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicBuilder {
    prefix: String,
    gateway_id: String,
}

impl TopicBuilder {
    pub fn new(gateway_id: String) -> Self {
        Self {
            prefix: "ae".to_string(), // aetheric-edge prefix
            gateway_id,
        }
    }

    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    pub fn health(&self) -> String {
        format!("{}/{}/health", self.prefix, self.gateway_id)
    }

    pub fn commands(&self) -> String {
        format!("{}/{}/cmd/+", self.prefix, self.gateway_id)
    }

    pub fn command_response(&self, command_id: &str) -> String {
        format!("{}/{}/cmd/{}/response", self.prefix, self.gateway_id, command_id)
    }

    pub fn telemetry(&self) -> String {
        format!("{}/{}/telemetry", self.prefix, self.gateway_id)
    }

    pub fn events(&self) -> String {
        format!("{}/{}/events", self.prefix, self.gateway_id)
    }

    pub fn ota_status(&self) -> String {
        format!("{}/{}/ota/status", self.prefix, self.gateway_id)
    }

    pub fn ssh_tunnel(&self, session_id: &str) -> String {
        format!("{}/{}/ssh/{}", self.prefix, self.gateway_id, session_id)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Topic {
    Health,
    Commands,
    CommandResponse(String),
    Telemetry,
    Events,
    OtaStatus,
    SshTunnel(String),
}

impl Topic {
    pub fn to_string(&self, builder: &TopicBuilder) -> String {
        match self {
            Topic::Health => builder.health(),
            Topic::Commands => builder.commands(),
            Topic::CommandResponse(cmd_id) => builder.command_response(cmd_id),
            Topic::Telemetry => builder.telemetry(),
            Topic::Events => builder.events(),
            Topic::OtaStatus => builder.ota_status(),
            Topic::SshTunnel(session_id) => builder.ssh_tunnel(session_id),
        }
    }
}

pub fn parse_command_topic(topic: &str, gateway_id: &str) -> Option<String> {
    let expected_prefix = format!("ae/{}/cmd/", gateway_id);
    if topic.starts_with(&expected_prefix) {
        let command_id = topic.strip_prefix(&expected_prefix)?;
        Some(command_id.to_string())
    } else {
        None
    }
}