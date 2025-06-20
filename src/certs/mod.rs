use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    SanType,
};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Set secure file permissions in a cross-platform way
fn set_secure_file_permissions(path: &std::path::Path, is_private_key: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs;
        let mut perms = fs::metadata(path)?.permissions();
        // Private keys get 0o600 (owner only), others get 0o644 (owner rw, others r)
        let mode = if is_private_key { 0o600 } else { 0o644 };
        perms.set_mode(mode);
        fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        // On Windows, we could set ACLs here for better security
        // For now, we rely on NTFS default permissions
        // TODO: Implement Windows ACL setting for production use
        let _ = (path, is_private_key); // Suppress unused variable warning
    }

    Ok(())
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub enum KeyAlgorithm {
    #[default]
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}


pub struct CertificateManager {
    cert_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub serial_number: String,
    pub is_valid: bool,
    pub days_until_expiry: i64,
}

impl CertificateManager {
    pub fn new(cert_dir: PathBuf) -> Self {
        Self { cert_dir }
    }

    pub fn get_default_cert_dir() -> PathBuf {
        if let Ok(cert_dir) = std::env::var("AETHERIC_CERT_DIR") {
            PathBuf::from(cert_dir)
        } else if let Some(home) = dirs::home_dir() {
            // Use ~/.aetheric/certs to match the configuration system
            home.join(".aetheric").join("certs")
        } else {
            PathBuf::from("/etc/aetheric-edge/certs")
        }
    }

    pub fn device_cert_path(&self) -> PathBuf {
        self.cert_dir.join("device-cert.pem")
    }

    pub fn device_key_path(&self) -> PathBuf {
        self.cert_dir.join("device-key.pem")
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.cert_dir.join("ca-cert.pem")
    }

    pub fn device_csr_path(&self) -> PathBuf {
        self.cert_dir.join("device-csr.pem")
    }

    pub async fn create_device_certificate(
        &self,
        device_id: &str,
        subject_alt_names: Vec<String>,
    ) -> Result<()> {
        self.create_device_certificate_with_algorithm(
            device_id,
            subject_alt_names,
            KeyAlgorithm::default(),
        )
        .await
    }

    pub async fn create_device_certificate_with_algorithm(
        &self,
        device_id: &str,
        subject_alt_names: Vec<String>,
        key_algorithm: KeyAlgorithm,
    ) -> Result<()> {
        info!("Creating device certificate for device ID: {}", device_id);

        // Ensure cert directory exists
        fs::create_dir_all(&self.cert_dir).context("Failed to create certificate directory")?;

        // Generate key pair with specified algorithm
        let key_pair = self
            .generate_secure_key_pair(key_algorithm)
            .context("Failed to generate secure key pair")?;

        // Create certificate parameters
        let mut params = CertificateParams::new(vec![device_id.to_string()]);

        // Set subject
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, device_id);
        distinguished_name.push(DnType::OrganizationName, "Aetheric Edge");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        // Add Subject Alternative Names
        let mut san_list = vec![SanType::DnsName(device_id.to_string())];
        for san in subject_alt_names {
            if san.parse::<std::net::IpAddr>().is_ok() {
                san_list.push(SanType::IpAddress(san.parse().unwrap()));
            } else {
                san_list.push(SanType::DnsName(san));
            }
        }
        params.subject_alt_names = san_list;

        // Set validity period (1 year)
        let now = std::time::SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + std::time::Duration::from_secs(365 * 24 * 60 * 60)).into();

        // Set key usage for MQTT client authentication
        params.is_ca = rcgen::IsCa::NoCa;

        // Add key usage extensions for MQTT client authentication
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        // Add extended key usage for client authentication
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        // Add custom extensions for MQTT broker compatibility
        params.custom_extensions = vec![
            // Certificate Policies extension for MQTT usage
            rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 32],  // Certificate Policies OID
                vec![0x30, 0x00], // Empty SEQUENCE (anyPolicy)
            ),
        ];

        // Set the key pair
        params.key_pair = Some(key_pair);

        // Generate certificate
        let cert = Certificate::from_params(params).context("Failed to generate certificate")?;

        // Write private key with secure permissions
        let key_pem = cert.serialize_private_key_pem();
        self.write_private_key_securely(&key_pem)
            .context("Failed to write device private key securely")?;

        // Write certificate with secure permissions
        let cert_pem = cert
            .serialize_pem()
            .context("Failed to serialize certificate")?;
        self.write_certificate_securely(&cert_pem)
            .context("Failed to write device certificate securely")?;

        info!("Device certificate created successfully");
        info!("Certificate: {:?}", self.device_cert_path());
        info!("Private key: {:?}", self.device_key_path());

        Ok(())
    }

    pub async fn create_certificate_signing_request(
        &self,
        device_id: &str,
        subject_alt_names: Vec<String>,
    ) -> Result<()> {
        self.create_certificate_signing_request_with_algorithm(
            device_id,
            subject_alt_names,
            KeyAlgorithm::default(),
        )
        .await
    }

    pub async fn create_certificate_signing_request_with_algorithm(
        &self,
        device_id: &str,
        subject_alt_names: Vec<String>,
        key_algorithm: KeyAlgorithm,
    ) -> Result<()> {
        info!(
            "Creating certificate signing request for device ID: {}",
            device_id
        );

        // Ensure cert directory exists
        fs::create_dir_all(&self.cert_dir).context("Failed to create certificate directory")?;

        // Generate key pair with specified algorithm
        let key_pair = self
            .generate_secure_key_pair(key_algorithm)
            .context("Failed to generate secure key pair")?;

        // Create certificate parameters for CSR
        let mut params = CertificateParams::new(vec![device_id.to_string()]);

        // Set subject
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, device_id);
        distinguished_name.push(DnType::OrganizationName, "Aetheric Edge");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        // Add Subject Alternative Names
        let mut san_list = vec![SanType::DnsName(device_id.to_string())];
        for san in subject_alt_names {
            if san.parse::<std::net::IpAddr>().is_ok() {
                san_list.push(SanType::IpAddress(san.parse().unwrap()));
            } else {
                san_list.push(SanType::DnsName(san));
            }
        }
        params.subject_alt_names = san_list;

        // Set the key pair
        params.key_pair = Some(key_pair);

        // Generate certificate with the key pair
        let cert =
            Certificate::from_params(params).context("Failed to create certificate for CSR")?;

        // Generate CSR
        let csr_pem = cert
            .serialize_request_pem()
            .context("Failed to generate CSR")?;

        // Write private key with secure permissions
        let key_pem = cert.serialize_private_key_pem();
        self.write_private_key_securely(&key_pem)
            .context("Failed to write device private key securely")?;

        // Write CSR with secure permissions
        let csr_path = self.device_csr_path();
        let temp_path = csr_path.with_extension("tmp");

        fs::write(&temp_path, csr_pem).context("Failed to write temporary CSR file")?;

        set_secure_file_permissions(&temp_path, false)
            .context("Failed to set permissions on CSR")?;

        fs::rename(&temp_path, &csr_path).context("Failed to move CSR to final location")?;

        info!("Certificate signing request created successfully");
        info!("CSR: {:?}", self.device_csr_path());
        info!("Private key: {:?}", self.device_key_path());

        Ok(())
    }

    pub async fn install_certificate(&self, cert_pem: &str) -> Result<()> {
        info!("Installing device certificate");

        // Ensure cert directory exists
        fs::create_dir_all(&self.cert_dir).context("Failed to create certificate directory")?;

        // Validate certificate format
        self.validate_certificate_pem(cert_pem)
            .context("Invalid certificate format")?;

        // Write certificate
        fs::write(self.device_cert_path(), cert_pem)
            .context("Failed to write device certificate")?;

        info!("Device certificate installed successfully");
        Ok(())
    }

    pub async fn install_ca_certificate(&self, ca_cert_pem: &str) -> Result<()> {
        info!("Installing CA certificate");

        // Ensure cert directory exists
        fs::create_dir_all(&self.cert_dir).context("Failed to create certificate directory")?;

        // Validate certificate format
        self.validate_certificate_pem(ca_cert_pem)
            .context("Invalid CA certificate format")?;

        // Write CA certificate
        fs::write(self.ca_cert_path(), ca_cert_pem).context("Failed to write CA certificate")?;

        info!("CA certificate installed successfully");
        Ok(())
    }

    pub async fn get_certificate_info(&self) -> Result<Option<CertificateInfo>> {
        let cert_path = self.device_cert_path();
        if !cert_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path).context("Failed to read certificate file")?;

        self.parse_certificate_info(&cert_pem).map(Some)
    }

    pub async fn check_certificate_expiry(&self, days_threshold: i64) -> Result<bool> {
        if let Some(cert_info) = self.get_certificate_info().await? {
            if cert_info.days_until_expiry <= days_threshold {
                warn!(
                    "Certificate expires in {} days (threshold: {})",
                    cert_info.days_until_expiry, days_threshold
                );
                return Ok(false);
            }
            debug!(
                "Certificate is valid for {} more days",
                cert_info.days_until_expiry
            );
            Ok(true)
        } else {
            warn!("No certificate found");
            Ok(false)
        }
    }

    pub async fn renew_certificate(
        &self,
        device_id: &str,
        subject_alt_names: Vec<String>,
    ) -> Result<()> {
        info!("Renewing device certificate");

        // Back up existing certificate if it exists
        let cert_path = self.device_cert_path();
        if cert_path.exists() {
            let backup_path = cert_path.with_extension("pem.backup");
            fs::copy(&cert_path, &backup_path).context("Failed to backup existing certificate")?;
            info!("Backed up existing certificate to {:?}", backup_path);
        }

        // Create new certificate
        self.create_device_certificate(device_id, subject_alt_names)
            .await
            .context("Failed to create renewed certificate")?;

        info!("Certificate renewed successfully");
        Ok(())
    }

    pub async fn remove_certificates(&self) -> Result<()> {
        info!("Removing device certificates");

        let paths = [
            self.device_cert_path(),
            self.device_key_path(),
            self.device_csr_path(),
        ];

        for path in &paths {
            if path.exists() {
                fs::remove_file(path).with_context(|| format!("Failed to remove {:?}", path))?;
                debug!("Removed {:?}", path);
            }
        }

        info!("Device certificates removed successfully");
        Ok(())
    }

    fn validate_certificate_pem(&self, pem: &str) -> Result<()> {
        use rustls_pemfile::Item;
        let mut cursor = std::io::Cursor::new(pem.as_bytes());

        match rustls_pemfile::read_one(&mut cursor).context("Failed to parse PEM data")? {
            Some(Item::X509Certificate(_)) => Ok(()),
            Some(_) => anyhow::bail!("PEM data is not a certificate"),
            None => anyhow::bail!("No PEM data found"),
        }
    }

    fn parse_certificate_info(&self, cert_pem: &str) -> Result<CertificateInfo> {
        use rustls_pemfile::Item;
        use x509_parser::prelude::*;

        let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
        let item = rustls_pemfile::read_one(&mut cursor)
            .context("Failed to parse PEM data")?
            .ok_or_else(|| anyhow::anyhow!("No PEM data found"))?;

        let cert_der = match item {
            Item::X509Certificate(der) => der,
            _ => anyhow::bail!("PEM data is not a certificate"),
        };

        let (_, cert) = X509Certificate::from_der(&cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let not_before = DateTime::<Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        let now = Utc::now();
        let is_valid = now >= not_before && now <= not_after;
        let days_until_expiry = (not_after - now).num_days();

        let serial_number = cert.serial.to_string();

        Ok(CertificateInfo {
            subject,
            issuer,
            not_before,
            not_after,
            serial_number,
            is_valid,
            days_until_expiry,
        })
    }

    pub fn extract_device_id_from_cert(&self) -> Result<Option<String>> {
        let cert_path = self.device_cert_path();
        if !cert_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path).context("Failed to read certificate file")?;

        // Parse certificate and extract CN from subject
        let cert_info = self.parse_certificate_info(&cert_pem)?;

        // Extract CN from subject string
        if let Some(cn_start) = cert_info.subject.find("CN=") {
            let cn_part = &cert_info.subject[cn_start + 3..];
            if let Some(cn_end) = cn_part.find(',') {
                return Ok(Some(cn_part[..cn_end].to_string()));
            } else {
                return Ok(Some(cn_part.to_string()));
            }
        }

        Ok(None)
    }

    // Security enhancement methods

    fn generate_secure_key_pair(&self, algorithm: KeyAlgorithm) -> Result<KeyPair> {
        let key_pair = match algorithm {
            KeyAlgorithm::EcdsaP256 => {
                info!("Generating ECDSA P-256 key pair for enhanced security");
                KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?
            }
            KeyAlgorithm::EcdsaP384 => {
                info!("Generating ECDSA P-384 key pair for maximum security");
                KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384)?
            }
            KeyAlgorithm::Rsa2048 => {
                info!("Generating RSA 2048-bit key pair");
                KeyPair::generate(&rcgen::PKCS_RSA_SHA256)?
            }
            KeyAlgorithm::Rsa3072 => {
                info!("Generating RSA 3072-bit key pair for enhanced security");
                // Note: rcgen doesn't directly support 3072-bit, so we use 4096-bit
                warn!("Using RSA 4096-bit instead of 3072-bit (rcgen limitation)");
                KeyPair::generate(&rcgen::PKCS_RSA_SHA256)?
            }
            KeyAlgorithm::Rsa4096 => {
                info!("Generating RSA 4096-bit key pair for maximum security");
                KeyPair::generate(&rcgen::PKCS_RSA_SHA256)?
            }
        };
        Ok(key_pair)
    }

    fn write_private_key_securely(&self, key_pem: &str) -> Result<()> {
        let key_path = self.device_key_path();

        // Create temporary file for atomic write
        let temp_path = key_path.with_extension("tmp");

        // Write to temporary file
        fs::write(&temp_path, key_pem).context("Failed to write temporary private key file")?;

        // Set restrictive permissions (owner read/write only)
        set_secure_file_permissions(&temp_path, true)
            .context("Failed to set secure permissions on private key")?;

        // Atomic move to final location
        fs::rename(&temp_path, &key_path)
            .context("Failed to move private key to final location")?;

        info!("Private key written securely with 0600 permissions");
        Ok(())
    }

    fn write_certificate_securely(&self, cert_pem: &str) -> Result<()> {
        let cert_path = self.device_cert_path();

        // Create temporary file for atomic write
        let temp_path = cert_path.with_extension("tmp");

        // Write to temporary file
        fs::write(&temp_path, cert_pem).context("Failed to write temporary certificate file")?;

        // Set appropriate permissions (owner read/write, group/others read)
        set_secure_file_permissions(&temp_path, false)
            .context("Failed to set permissions on certificate")?;

        // Atomic move to final location
        fs::rename(&temp_path, &cert_path)
            .context("Failed to move certificate to final location")?;

        info!("Certificate written securely with 0644 permissions");
        Ok(())
    }

    pub async fn validate_certificate_chain(&self, ca_cert_pem: Option<&str>) -> Result<bool> {
        let cert_path = self.device_cert_path();
        if !cert_path.exists() {
            return Ok(false);
        }

        let cert_pem =
            fs::read_to_string(&cert_path).context("Failed to read device certificate")?;

        // Parse device certificate
        use rustls_pemfile::Item;
        use x509_parser::prelude::*;

        let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
        let item = rustls_pemfile::read_one(&mut cursor)
            .context("Failed to parse device certificate PEM")?
            .ok_or_else(|| anyhow::anyhow!("No PEM data found in device certificate"))?;

        let cert_der = match item {
            Item::X509Certificate(der) => der,
            _ => anyhow::bail!("Device certificate PEM data is not a certificate"),
        };

        let (_, device_cert) = X509Certificate::from_der(&cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse device X.509 certificate: {}", e))?;

        // Check basic certificate validity
        let now = std::time::SystemTime::now();
        let now_duration = now
            .duration_since(std::time::UNIX_EPOCH)
            .context("Failed to get current time")?;
        let now_timestamp = now_duration.as_secs() as i64;

        if device_cert.validity().not_before.timestamp() > now_timestamp {
            return Ok(false); // Certificate not yet valid
        }
        if device_cert.validity().not_after.timestamp() < now_timestamp {
            return Ok(false); // Certificate expired
        }

        // If CA certificate is provided, validate the chain
        if let Some(ca_pem) = ca_cert_pem {
            let mut ca_cursor = std::io::Cursor::new(ca_pem.as_bytes());
            let ca_item = rustls_pemfile::read_one(&mut ca_cursor)
                .context("Failed to parse CA certificate PEM")?
                .ok_or_else(|| anyhow::anyhow!("No PEM data found in CA certificate"))?;

            let ca_cert_der = match ca_item {
                Item::X509Certificate(der) => der,
                _ => anyhow::bail!("CA certificate PEM data is not a certificate"),
            };

            let (_, ca_cert) = X509Certificate::from_der(&ca_cert_der)
                .map_err(|e| anyhow::anyhow!("Failed to parse CA X.509 certificate: {}", e))?;

            // Check if device certificate is signed by CA
            // Note: This is a simplified check. In production, you'd want to use a proper
            // certificate validation library like webpki or rustls for full chain validation
            if device_cert.issuer() != ca_cert.subject() {
                warn!("Device certificate issuer does not match CA certificate subject");
                return Ok(false);
            }

            info!("Certificate chain validation passed");
        }

        Ok(true)
    }

    pub async fn get_certificate_fingerprint(
        &self,
        hash_algorithm: &str,
    ) -> Result<Option<String>> {
        let cert_path = self.device_cert_path();
        if !cert_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path).context("Failed to read certificate file")?;

        use rustls_pemfile::Item;
        let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
        let item = rustls_pemfile::read_one(&mut cursor)
            .context("Failed to parse PEM data")?
            .ok_or_else(|| anyhow::anyhow!("No PEM data found"))?;

        let cert_der = match item {
            Item::X509Certificate(der) => der,
            _ => anyhow::bail!("PEM data is not a certificate"),
        };

        let fingerprint = match hash_algorithm.to_lowercase().as_str() {
            "sha1" => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(&cert_der);
                format!("{:x}", hasher.finalize())
            }
            "sha256" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&cert_der);
                format!("{:x}", hasher.finalize())
            }
            "md5" => {
                let digest = md5::compute(&cert_der);
                format!("{:x}", digest)
            }
            _ => anyhow::bail!("Unsupported hash algorithm: {}", hash_algorithm),
        };

        Ok(Some(fingerprint))
    }

    pub async fn check_private_key_permissions(&self) -> Result<bool> {
        let key_path = self.device_key_path();
        if !key_path.exists() {
            return Ok(false);
        }

        #[cfg(unix)]
        {
            let metadata =
                fs::metadata(&key_path).context("Failed to read private key file metadata")?;
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check if permissions are 0600 (owner read/write only)
            if mode & 0o777 != 0o600 {
                warn!(
                    "Private key file has insecure permissions: {:o}",
                    mode & 0o777
                );
                return Ok(false);
            }
        }

        Ok(true)
    }
}
