# Aetheric Edge Windows Installation Script
# PowerShell script for installing Aetheric Edge on Windows

param(
    [switch]$Force,
    [string]$InstallPath = "C:\Program Files\AethericEdge",
    [string]$UserDataPath = "$env:USERPROFILE\.aetheric"
)

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

Write-Host "================================================================" -ForegroundColor Blue
Write-Host "             Aetheric Edge Windows Installation" -ForegroundColor Blue  
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "This script will install Aetheric Edge with:" -ForegroundColor Yellow
Write-Host "  • Aetheric Edge Agent Windows Service" -ForegroundColor Yellow
Write-Host "  • Mosquitto MQTT Broker (if not present)" -ForegroundColor Yellow
Write-Host "  • Configuration management tools" -ForegroundColor Yellow
Write-Host ""

# Confirm installation
$confirmation = Read-Host "Do you want to continue? (y/N)"
if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
    Write-Host "Installation cancelled." -ForegroundColor Red
    exit 0
}

# Create directories
Write-Host "Creating directory structure..." -ForegroundColor Green
$directories = @(
    $InstallPath,
    "$UserDataPath\data",
    "$UserDataPath\logs", 
    "$UserDataPath\certs",
    "$UserDataPath\plugins",
    "$UserDataPath\temp"
)

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Gray
    }
}

# Install Mosquitto if not present
Write-Host "Checking for Mosquitto MQTT Broker..." -ForegroundColor Green
$mosquittoPath = Get-Command mosquitto -ErrorAction SilentlyContinue
if (-not $mosquittoPath) {
    Write-Host "Mosquitto not found. Checking for Chocolatey..." -ForegroundColor Yellow
    $chocoPath = Get-Command choco -ErrorAction SilentlyContinue
    if ($chocoPath) {
        Write-Host "Installing Mosquitto via Chocolatey..." -ForegroundColor Yellow
        choco install mosquitto -y
    } else {
        Write-Warning @"
Mosquitto MQTT broker is not installed and Chocolatey is not available.
Please install Mosquitto manually:

1. Download from: https://mosquitto.org/download/
2. Or install Chocolatey and run: choco install mosquitto
3. Then re-run this installation script

Installation will continue, but MQTT functionality may not work without Mosquitto.
"@
    }
} else {
    Write-Host "✓ Mosquitto found at: $($mosquittoPath.Source)" -ForegroundColor Green
}

# Copy binaries (assuming they're in the same directory or downloaded)
Write-Host "Installing Aetheric Edge binaries..." -ForegroundColor Green
if (Test-Path ".\aetheric-agent.exe" -and Test-Path ".\aetheric.exe") {
    Copy-Item ".\aetheric-agent.exe" "$InstallPath\aetheric-agent.exe" -Force
    Copy-Item ".\aetheric.exe" "$InstallPath\aetheric.exe" -Force
    Write-Host "✓ Binaries installed to $InstallPath" -ForegroundColor Green
} else {
    Write-Warning "Binary files not found. Please ensure aetheric-agent.exe and aetheric.exe are in the current directory."
}

# Add to PATH
Write-Host "Adding Aetheric Edge to PATH..." -ForegroundColor Green
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallPath", "Machine")
    Write-Host "✓ Added to system PATH" -ForegroundColor Green
}

# Create default configuration
Write-Host "Creating default configuration..." -ForegroundColor Green
$configContent = @"
# Aetheric Edge Windows Configuration
# Generated on $(Get-Date)

[gateway]
id = "aetheric-$(hostname)-$(Get-Random -Maximum 999999)"
name = "Aetheric Edge Windows Device"
location = "Windows Environment"
description = "Aetheric Edge IoT Gateway running on Windows"

[mqtt]
host = "localhost"
port = 1884
username = "aetheric"
password = "aetheric-$(Get-Random -Maximum 999999)"
tls = false
ca_cert_path = "$($UserDataPath.Replace('\', '/'))/certs/ca-cert.pem"
client_cert_path = "$($UserDataPath.Replace('\', '/'))/certs/device-cert.pem"
client_key_path = "$($UserDataPath.Replace('\', '/'))/certs/device-key.pem"

[certificates]
cert_dir = "$($UserDataPath.Replace('\', '/'))/certs"
auto_renew = true
renew_days_threshold = 30

[health]
report_interval_seconds = 30
metrics_enabled = true

[plugins]
install_dir = "$($UserDataPath.Replace('\', '/'))/plugins"
temp_dir = "$($UserDataPath.Replace('\', '/'))/temp"
docker_enabled = true
max_concurrent_installs = 2

[ssh]
enabled = false
port = 22
max_sessions = 5
session_timeout_minutes = 60
"@

$configPath = "$UserDataPath\aetheric.toml"
$configContent | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "✓ Configuration created at: $configPath" -ForegroundColor Green

# Install Windows Service
Write-Host "Installing Aetheric Edge Windows Service..." -ForegroundColor Green
$serviceName = "AethericEdgeAgent"
$serviceDisplayName = "Aetheric Edge Agent"
$serviceDescription = "MQTT-based edge computing agent for IoT device management"
$servicePath = "`"$InstallPath\aetheric-agent.exe`" --config `"$configPath`""

# Remove existing service if it exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Removing existing service..." -ForegroundColor Yellow
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep 2
}

# Create the service
$result = sc.exe create $serviceName binPath= $servicePath DisplayName= $serviceDisplayName start= auto
if ($LASTEXITCODE -eq 0) {
    # Set service description
    sc.exe description $serviceName $serviceDescription | Out-Null
    
    # Configure service recovery options
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    
    Write-Host "✓ Windows Service '$serviceDisplayName' installed successfully" -ForegroundColor Green
} else {
    Write-Error "Failed to install Windows Service. Error: $result"
}

# Create Mosquitto configuration for Aetheric
Write-Host "Configuring Mosquitto for Aetheric Edge..." -ForegroundColor Green
$mosquittoConfigDir = "$UserDataPath\mosquitto-conf"
if (!(Test-Path $mosquittoConfigDir)) {
    New-Item -ItemType Directory -Path $mosquittoConfigDir -Force | Out-Null
}

$mosquittoConfig = @"
# Aetheric Edge MQTT Configuration for Windows

# Basic settings
persistence true
persistence_location $($UserDataPath.Replace('\', '/'))/data/mosquitto/
log_dest file $($UserDataPath.Replace('\', '/'))/logs/mosquitto.log
log_type error
log_type warning  
log_type notice
log_type information
log_timestamp true
connection_messages true

# Security
allow_anonymous false
password_file $($UserDataPath.Replace('\', '/'))/mosquitto.passwd

# Aetheric listener
listener 1884 127.0.0.1
protocol mqtt

# Message limits
message_size_limit 100000000
max_connections 1000
max_inflight_messages 100
max_queued_messages 1000

# Persistence settings
autosave_interval 1800
autosave_on_changes false
persistent_client_expiration 2h
"@

$mosquittoConfig | Out-File -FilePath "$mosquittoConfigDir\aetheric.conf" -Encoding UTF8

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "             Aetheric Edge Installation Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Installation Summary:" -ForegroundColor Yellow
Write-Host "  • Installation Path: $InstallPath" -ForegroundColor Gray
Write-Host "  • User Data Path: $UserDataPath" -ForegroundColor Gray
Write-Host "  • Configuration: $configPath" -ForegroundColor Gray
Write-Host "  • Service Name: $serviceName" -ForegroundColor Gray
Write-Host ""
Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Configure your device:" -ForegroundColor Gray
Write-Host "     aetheric setup" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Start the service:" -ForegroundColor Gray
Write-Host "     Start-Service $serviceName" -ForegroundColor Cyan
Write-Host "     # or use Services.msc GUI" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Check service status:" -ForegroundColor Gray
Write-Host "     Get-Service $serviceName" -ForegroundColor Cyan
Write-Host "     sc query $serviceName" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. View logs:" -ForegroundColor Gray
Write-Host "     Get-EventLog -LogName Application -Source '$serviceName'" -ForegroundColor Cyan
Write-Host "     Get-Content '$UserDataPath\logs\aetheric-agent.log'" -ForegroundColor Cyan
Write-Host ""
Write-Host "  5. Service management:" -ForegroundColor Gray
Write-Host "     Start-Service $serviceName" -ForegroundColor Cyan
Write-Host "     Stop-Service $serviceName" -ForegroundColor Cyan
Write-Host "     Restart-Service $serviceName" -ForegroundColor Cyan
Write-Host ""
Write-Host "📖 Documentation:" -ForegroundColor Yellow
Write-Host "  • Configuration file: $configPath" -ForegroundColor Gray
Write-Host "  • MQTT config: $mosquittoConfigDir" -ForegroundColor Gray
Write-Host "  • User data: $UserDataPath" -ForegroundColor Gray
Write-Host "  • Service logs: Windows Event Viewer > Application" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  Note: Run 'aetheric setup' to complete device configuration" -ForegroundColor Red