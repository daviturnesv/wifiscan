use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::interval;
use tracing::{debug, warn};

// ============================================================================
// CLI Enums
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BandFilter {
    #[clap(name = "2.4")]
    #[serde(rename = "2.4")]
    Band2_4,
    #[clap(name = "5")]
    #[serde(rename = "5")]
    Band5,
    #[clap(name = "6")]
    #[serde(rename = "6")]
    Band6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityFilter {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SortBy {
    #[default]
    Signal,
    Ssid,
    Channel,
    Security,
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub default_interface: Option<String>,
    pub default_format: String,
    pub default_interval_ms: u64,
    pub default_min_signal: Option<i32>,
    pub scan_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_interface: None,
            default_format: "text".to_string(),
            default_interval_ms: 2000,
            default_min_signal: Some(-80),
            scan_timeout_ms: 10000,
        }
    }
}

impl Config {
    pub async fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        if config_path.exists() {
            let content = tokio::fs::read_to_string(&config_path).await?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub async fn create_default(path: &str) -> Result<()> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        let expanded = shellexpand::tilde(path).to_string();
        if let Some(parent) = std::path::Path::new(&expanded).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(expanded, content).await?;
        Ok(())
    }

    fn config_path() -> Result<std::path::PathBuf> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("wifiscan");
        Ok(config_dir.join("config.toml"))
    }
}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    pub interface: Option<String>,
    pub min_signal: Option<i32>,
    pub band_filter: Option<BandFilter>,
    pub security_filter: Option<SecurityFilter>,
    pub sort_by: SortBy,
    pub show_hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub timestamp: u64,
    pub interface: String,
    pub scan_duration_ms: u64,
    pub networks: Vec<NetworkInfo>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_networks: usize,
    pub by_band: HashMap<String, usize>,
    pub by_security: HashMap<String, usize>,
    pub strongest_signal: Option<i32>,
    pub average_signal: Option<f32>,
    pub channel_utilization: HashMap<u32, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub bssid: String,
    pub ssid: String,
    pub signal_dbm: i32,
    pub frequency_mhz: u32,
    pub channel: u32,
    pub band: String,
    pub width: String,
    pub security: String,
    pub security_flags: Vec<String>,
    pub wps: bool,
    pub rates: Vec<String>,
    pub vendor: Option<String>,
    pub last_seen: u64,
    pub quality_percent: u8,
    pub noise_floor_dbm: Option<i32>,
    pub snr_db: Option<f32>,
}

impl NetworkInfo {
    pub fn from_platform(info: PlatformNetworkInfo, show_hidden: bool) -> Option<Self> {
        if info.ssid.is_empty() && !show_hidden {
            return None;
        }

        let channel = Self::frequency_to_channel(info.frequency_mhz);
        let band = Self::frequency_to_band(info.frequency_mhz);
        let width = Self::channel_width(info.frequency_mhz);
        let quality = Self::signal_to_quality(info.signal_dbm);
        let snr = info.noise_floor_dbm.map(|n| (info.signal_dbm - n) as f32);
        let vendor = Self::lookup_vendor(&info.bssid);

        Some(Self {
            bssid: info.bssid,
            ssid: info.ssid.clone(),
            signal_dbm: info.signal_dbm,
            frequency_mhz: info.frequency_mhz,
            channel,
            band,
            width,
            security: info.security,
            security_flags: info.security_flags,
            wps: info.wps,
            rates: info.rates,
            vendor,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs(),
            quality_percent: quality,
            noise_floor_dbm: info.noise_floor_dbm,
            snr_db: snr,
        })
    }

    pub fn frequency_to_channel(freq: u32) -> u32 {
        match freq {
            2412..=2484 => (freq - 2412) / 5 + 1,
            5180..=5825 => (freq - 5180) / 5 + 36,
            5935..=7115 => (freq - 5935) / 5 + 1,
            _ => 0,
        }
    }

    fn frequency_to_band(freq: u32) -> String {
        match freq {
            2400..=2499 => "2.4 GHz".to_string(),
            5000..=5899 => "5 GHz".to_string(),
            5900..=7200 => "6 GHz".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    fn channel_width(freq: u32) -> String {
        match freq {
            2400..=2499 => "20 MHz".to_string(),
            5000..=5899 => "80 MHz".to_string(),
            5900..=7200 => "160 MHz".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    fn signal_to_quality(signal: i32) -> u8 {
        let quality = ((signal + 90) as f32 / 60.0 * 100.0).clamp(0.0, 100.0);
        quality as u8
    }

    fn lookup_vendor(_bssid: &str) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAnalysis {
    pub channel: u32,
    pub band: String,
    pub networks: usize,
    pub avg_signal: f32,
    pub max_signal: i32,
    pub min_signal: i32,
    pub overlap_score: f32,
    pub utilization_percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub interface: String,
    pub duration_secs: u64,
    pub scan_count: u32,
    pub channels: Vec<ChannelAnalysis>,
    pub recommendations: Vec<String>,
    pub interference_detected: bool,
}

// ============================================================================
// Platform Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessInterface {
    pub name: String,
    pub description: String,
    pub status: String,
    pub phy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformNetworkInfo {
    pub bssid: String,
    pub ssid: String,
    pub signal_dbm: i32,
    pub frequency_mhz: u32,
    pub security: String,
    pub security_flags: Vec<String>,
    pub wps: bool,
    pub rates: Vec<String>,
    pub noise_floor_dbm: Option<i32>,
}

#[async_trait]
pub trait PlatformScanner: Send + Sync {
    async fn scan(&self, interface: &str, config: &ScanConfig) -> Result<Vec<PlatformNetworkInfo>>;
    async fn list_interfaces(&self) -> Result<Vec<WirelessInterface>>;
    fn default_interface(&self) -> Option<String>;
}

// Linux nl80211 scanner using `iw` command
pub struct LinuxScanner {
    interfaces_cache: Mutex<Option<Vec<WirelessInterface>>>,
}

impl LinuxScanner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            interfaces_cache: Mutex::new(None),
        })
    }

    fn parse_iw_output(&self, output: &str) -> Result<Vec<PlatformNetworkInfo>> {
        let mut networks = Vec::new();
        let mut current: Option<PlatformNetworkInfo> = None;

        for line in output.lines() {
            let line = line.trim();

            if line.starts_with("BSS ") {
                if let Some(net) = current.take() {
                    networks.push(net);
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let bssid = parts[1].trim_end_matches(|c: char| c == '(' || c == ')');
                    current = Some(PlatformNetworkInfo {
                        bssid: bssid.to_string(),
                        ssid: String::new(),
                        signal_dbm: -100,
                        frequency_mhz: 0,
                        security: "Open".to_string(),
                        security_flags: Vec::new(),
                        wps: false,
                        rates: Vec::new(),
                        noise_floor_dbm: None,
                    });
                }
            }

            if let Some(ref mut net) = current {
                if line.starts_with("SSID: ") {
                    net.ssid = line[6..].to_string();
                } else if line.starts_with("freq: ") {
                    net.frequency_mhz = line[6..].parse().unwrap_or(0);
                } else if line.starts_with("signal: ") {
                    let signal_str = line[8..].trim_end_matches(" dBm");
                    net.signal_dbm = signal_str.parse().unwrap_or(-100);
                } else if line.starts_with("capability: ") {
                    let caps = &line[12..];
                    if caps.contains("Privacy") {
                        net.security = "WEP/WPA".to_string();
                    }
                } else if line.contains("WPA:") {
                    net.security = "WPA".to_string();
                } else if line.contains("RSN:") {
                    net.security = "WPA2".to_string();
                } else if line.starts_with("WPS:") {
                    net.wps = true;
                } else if line.starts_with("noise: ") {
                    let noise_str = line[7..].trim_end_matches(" dBm");
                    net.noise_floor_dbm = noise_str.parse().ok();
                } else if line.starts_with("rates: ") {
                    net.rates = line[7..].split(',').map(|s| s.trim().to_string()).collect();
                }
            }
        }

        if let Some(net) = current {
            networks.push(net);
        }

        Ok(networks)
    }

    fn parse_ip_link(&self, output: &str) -> Vec<WirelessInterface> {
        let mut interfaces = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.contains(": wlan") || line.contains(": wlp") || line.contains(": wlx") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim_end_matches(':').to_string();
                    let status = if line.contains("state UP") {
                        "UP"
                    } else {
                        "DOWN"
                    };

                    interfaces.push(WirelessInterface {
                        name,
                        description: "Wireless interface".to_string(),
                        status: status.to_string(),
                        phy: None,
                    });
                }
            }
        }

        interfaces
    }
}

#[async_trait]
impl PlatformScanner for LinuxScanner {
    async fn scan(&self, interface: &str, config: &ScanConfig) -> Result<Vec<PlatformNetworkInfo>> {
        let output = TokioCommand::new("iw")
            .args(["dev", interface, "scan"])
            .output()
            .await
            .context("Failed to run iw scan")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("permission denied") || stderr.contains("Operation not permitted") {
                warn!("iw scan needs root, trying with sudo");
                let output = TokioCommand::new("sudo")
                    .args(["iw", "dev", interface, "scan"])
                    .output()
                    .await
                    .context("Failed to run sudo iw scan")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("sudo iw scan failed: {}", stderr);
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                return self.parse_iw_output(&stdout);
            } else {
                anyhow::bail!("iw scan failed: {}", stderr);
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut networks = self.parse_iw_output(&stdout)?;

        if let Some(min_signal) = config.min_signal {
            networks.retain(|n| n.signal_dbm >= min_signal);
        }

        if let Some(ref band) = config.band_filter {
            networks.retain(|n| {
                let channel = NetworkInfo::frequency_to_channel(n.frequency_mhz);
                match band {
                    BandFilter::Band2_4 => channel >= 1 && channel <= 14,
                    BandFilter::Band5 => channel >= 36 && channel <= 165,
                    BandFilter::Band6 => channel >= 1 && channel <= 233,
                }
            });
        }

        if let Some(ref sec) = config.security_filter {
            networks.retain(|n| {
                let sec_str = n.security.to_lowercase();
                match sec {
                    SecurityFilter::Open => sec_str == "open" || sec_str.is_empty(),
                    SecurityFilter::Wep => sec_str.contains("wep"),
                    SecurityFilter::Wpa => sec_str.contains("wpa"),
                    SecurityFilter::Wpa2 => sec_str.contains("wpa2") || sec_str.contains("rsn"),
                    SecurityFilter::Wpa3 => sec_str.contains("wpa3") || sec_str.contains("sae"),
                }
            });
        }

        match config.sort_by {
            SortBy::Signal => networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm)),
            SortBy::Ssid => networks.sort_by(|a, b| a.ssid.cmp(&b.ssid)),
            SortBy::Channel => {
                networks.sort_by(|a, b| {
                    let ca = NetworkInfo::frequency_to_channel(a.frequency_mhz);
                    let cb = NetworkInfo::frequency_to_channel(b.frequency_mhz);
                    ca.cmp(&cb)
                });
            }
            SortBy::Security => networks.sort_by(|a, b| a.security.cmp(&b.security)),
        }

        Ok(networks)
    }

    async fn list_interfaces(&self) -> Result<Vec<WirelessInterface>> {
        if let Ok(cache) = self.interfaces_cache.lock() {
            if let Some(ref cached) = *cache {
                return Ok(cached.clone());
            }
        }

        let output = TokioCommand::new("ip")
            .args(["link", "show"])
            .output()
            .await
            .context("Failed to run ip link")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = self.parse_ip_link(&stdout);

        if let Ok(iw_output) = TokioCommand::new("iw").args(["dev"]).output().await {
            let iw_stdout = String::from_utf8_lossy(&iw_output.stdout);
            let mut current_phy: Option<String> = None;

            for line in iw_stdout.lines() {
                let line = line.trim();
                if line.starts_with("phy #") {
                    current_phy = line.split_whitespace().nth(2).map(|s| s.to_string());
                } else if line.starts_with("Interface ") {
                    if let Some(iface_name) = line.split_whitespace().nth(1) {
                        for iface in &mut interfaces {
                            if iface.name == iface_name {
                                iface.phy = current_phy.clone();
                                iface.description = format!(
                                    "Wireless interface (phy: {})",
                                    current_phy.as_deref().unwrap_or("unknown")
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Ok(mut cache) = self.interfaces_cache.lock() {
            *cache = Some(interfaces.clone());
        }

        Ok(interfaces)
    }

    fn default_interface(&self) -> Option<String> {
        Some("wlan0".to_string())
    }
}

// Fallback scanner using nmcli
pub struct NmcliScanner;

#[async_trait]
impl PlatformScanner for NmcliScanner {
    async fn scan(&self, interface: &str, config: &ScanConfig) -> Result<Vec<PlatformNetworkInfo>> {
        let _ = TokioCommand::new("nmcli")
            .args(["dev", "wifi", "rescan", "ifname", interface])
            .output()
            .await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let output = TokioCommand::new("nmcli")
            .args([
                "-t",
                "-f",
                "SSID,BSSID,SIGNAL,SECURITY,FREQ,RATE",
                "dev",
                "wifi",
                "list",
                "ifname",
                interface,
            ])
            .output()
            .await
            .context("Failed to run nmcli")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut networks = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 5 {
                let ssid = parts[0];
                let bssid = parts[1];
                let signal: i32 = parts[2].parse().unwrap_or(0);
                let security = parts[3];
                let freq: u32 = parts[4].parse().unwrap_or(0);
                let rate = parts.get(5).copied().unwrap_or("");

                let signal_dbm = (signal as f32 / 2.0 - 100.0) as i32;

                networks.push(PlatformNetworkInfo {
                    bssid: bssid.to_string(),
                    ssid: ssid.to_string(),
                    signal_dbm,
                    frequency_mhz: freq,
                    security: security.to_string(),
                    security_flags: vec![],
                    wps: false,
                    rates: vec![rate.to_string()],
                    noise_floor_dbm: None,
                });
            }
        }

        if let Some(min_signal) = config.min_signal {
            networks.retain(|n| n.signal_dbm >= min_signal);
        }

        Ok(networks)
    }

    async fn list_interfaces(&self) -> Result<Vec<WirelessInterface>> {
        let output = TokioCommand::new("nmcli")
            .args(["-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"])
            .output()
            .await
            .context("Failed to run nmcli")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[1] == "wifi" {
                interfaces.push(WirelessInterface {
                    name: parts[0].to_string(),
                    description: "WiFi interface (NetworkManager)".to_string(),
                    status: parts[2].to_string(),
                    phy: None,
                });
            }
        }

        Ok(interfaces)
    }

    fn default_interface(&self) -> Option<String> {
        Some("wlan0".to_string())
    }
}

// Factory function
pub fn create_scanner() -> Result<Box<dyn PlatformScanner>> {
    if std::path::Path::new("/usr/sbin/iw").exists() || std::path::Path::new("/usr/bin/iw").exists()
    {
        return Ok(Box::new(LinuxScanner::new()?));
    }

    if std::path::Path::new("/usr/bin/nmcli").exists() {
        return Ok(Box::new(NmcliScanner));
    }

    anyhow::bail!("No WiFi scanning backend available (need iw or nmcli)")
}

// ============================================================================
// Scan Engine
// ============================================================================

pub struct ScanEngine {
    scanner: Box<dyn PlatformScanner>,
}

impl ScanEngine {
    pub fn new(scanner: Box<dyn PlatformScanner>) -> Self {
        Self { scanner }
    }

    pub async fn scan_once(&mut self, config: ScanConfig) -> Result<ScanResult> {
        let interface = config
            .interface
            .clone()
            .or_else(|| self.scanner.default_interface())
            .ok_or_else(|| anyhow::anyhow!("No wireless interface specified or found"))?;

        let start = std::time::Instant::now();
        let networks = self.scanner.scan(&interface, &config).await?;
        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let network_infos: Vec<NetworkInfo> = networks
            .into_iter()
            .filter_map(|n| NetworkInfo::from_platform(n, config.show_hidden))
            .collect();

        let mut by_band = HashMap::new();
        let mut by_security = HashMap::new();
        let mut channel_util = HashMap::new();
        let mut signals = Vec::new();

        for net in &network_infos {
            *by_band.entry(net.band.clone()).or_insert(0) += 1;
            *by_security.entry(net.security.clone()).or_insert(0) += 1;
            *channel_util.entry(net.channel).or_insert(0) += 1;
            signals.push(net.signal_dbm as f32);
        }

        let strongest = signals.iter().cloned().fold(f32::MIN, f32::max);
        let average = if !signals.is_empty() {
            Some(signals.iter().sum::<f32>() / signals.len() as f32)
        } else {
            None
        };

        let summary = ScanSummary {
            total_networks: network_infos.len(),
            by_band,
            by_security,
            strongest_signal: if signals.is_empty() {
                None
            } else {
                Some(strongest as i32)
            },
            average_signal: average,
            channel_utilization: channel_util,
        };

        Ok(ScanResult {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            interface,
            scan_duration_ms,
            networks: network_infos,
            summary,
        })
    }

    pub async fn monitor(
        &mut self,
        config: ScanConfig,
        interval_duration: Duration,
        count: u32,
        track_bssids: Vec<String>,
        format: OutputFormat,
        output_file: Option<String>,
    ) -> Result<()> {
        let formatter = OutputFormatter::new(format);
        let mut interval_timer = interval(interval_duration);
        let mut scan_count = 0;

        let mut file = if let Some(ref path) = output_file {
            let expanded = shellexpand::tilde(path).to_string();
            if let Some(parent) = std::path::Path::new(&expanded).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            Some(
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(expanded)
                    .await?,
            )
        } else {
            None
        };

        loop {
            interval_timer.tick().await;

            let result = self.scan_once(config.clone()).await?;

            let filtered_result = if !track_bssids.is_empty() {
                let mut filtered = result.clone();
                filtered
                    .networks
                    .retain(|n| track_bssids.iter().any(|t| &n.bssid == t));
                filtered.summary.total_networks = filtered.networks.len();
                filtered
            } else {
                result
            };

            let content = match format {
                OutputFormat::Text => formatter.format_text(&filtered_result),
                OutputFormat::Json => formatter.format_json(&filtered_result)?,
                OutputFormat::Csv => formatter.format_csv(&filtered_result)?,
            };

            if let Some(ref mut f) = file {
                use tokio::io::AsyncWriteExt;
                f.write_all(content.as_bytes()).await?;
                f.write_all(b"\n").await?;
                f.flush().await?;
            } else {
                println!("{}", content);
            }

            scan_count += 1;
            if count > 0 && scan_count >= count {
                break;
            }
        }

        Ok(())
    }

    pub async fn analyze(
        &mut self,
        interface: Option<String>,
        duration: Duration,
    ) -> Result<AnalysisResult> {
        let interface = interface
            .or_else(|| self.scanner.default_interface())
            .ok_or_else(|| anyhow::anyhow!("No wireless interface found"))?;

        let start = std::time::Instant::now();
        let mut channel_data: HashMap<u32, Vec<NetworkInfo>> = HashMap::new();
        let mut scan_count = 0;

        while start.elapsed() < duration {
            let config = ScanConfig::default();
            let result = self.scanner.scan(&interface, &config).await?;

            for net in result {
                if let Some(info) = NetworkInfo::from_platform(net, false) {
                    channel_data.entry(info.channel).or_default().push(info);
                }
            }

            scan_count += 1;
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        let mut channels = Vec::new();
        for (channel, networks) in channel_data {
            if networks.is_empty() {
                continue;
            }

            let band = if channel <= 14 {
                "2.4GHz"
            } else if channel <= 165 {
                "5GHz"
            } else {
                "6GHz"
            };
            let signals: Vec<i32> = networks.iter().map(|n| n.signal_dbm).collect();
            let avg_signal = signals.iter().sum::<i32>() as f32 / signals.len() as f32;
            let max_signal = *signals.iter().max().unwrap_or(&0);
            let min_signal = *signals.iter().min().unwrap_or(&0);

            let overlap_score = (networks.len() as f32 - 1.0).max(0.0) * 10.0;
            let utilization = (networks.len() as f32 / 3.0).min(100.0);

            channels.push(ChannelAnalysis {
                channel,
                band: band.to_string(),
                networks: networks.len(),
                avg_signal,
                max_signal,
                min_signal,
                overlap_score,
                utilization_percent: utilization as u32,
            });
        }

        channels.sort_by_key(|c| c.channel);

        let interference = channels
            .iter()
            .any(|c| c.networks > 3 || c.overlap_score > 50.0);

        let mut recommendations = Vec::new();
        if interference {
            recommendations
                .push("High interference detected - consider changing channel".to_string());
        }

        let best_24: Vec<_> = channels
            .iter()
            .filter(|c| c.band == "2.4GHz" && c.networks <= 1)
            .collect();
        let best_5: Vec<_> = channels
            .iter()
            .filter(|c| c.band == "5GHz" && c.networks <= 1)
            .collect();

        if !best_24.is_empty() {
            recommendations.push(format!(
                "Best 2.4GHz channels: {}",
                best_24
                    .iter()
                    .map(|c| c.channel.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !best_5.is_empty() {
            recommendations.push(format!(
                "Best 5GHz channels: {}",
                best_5
                    .iter()
                    .map(|c| c.channel.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if recommendations.is_empty() {
            recommendations.push("No significant interference detected".to_string());
        }

        Ok(AnalysisResult {
            interface,
            duration_secs: duration.as_secs(),
            scan_count,
            interference_detected: interference,
            channels,
            recommendations,
        })
    }
}

// ============================================================================
// Output Formatter
// ============================================================================

pub struct OutputFormatter {
    format: OutputFormat,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    pub async fn output(&self, result: &ScanResult, output_file: Option<&str>) -> Result<()> {
        let content = match self.format {
            OutputFormat::Text => self.format_text(result),
            OutputFormat::Json => self.format_json(result)?,
            OutputFormat::Csv => self.format_csv(result)?,
        };

        if let Some(path) = output_file {
            self.write_file(path, &content).await?;
        } else {
            println!("{}", content);
        }

        Ok(())
    }

    pub async fn output_analysis(
        &self,
        result: &AnalysisResult,
        output_file: Option<&str>,
    ) -> Result<()> {
        let content = match self.format {
            OutputFormat::Text => self.format_analysis_text(result),
            OutputFormat::Json => self.format_analysis_json(result)?,
            OutputFormat::Csv => self.format_analysis_csv(result)?,
        };

        if let Some(path) = output_file {
            self.write_file(path, &content).await?;
        } else {
            println!("{}", content);
        }

        Ok(())
    }

    pub fn format_text(&self, result: &ScanResult) -> String {
        let mut out = String::new();

        out.push_str("=== WiFi Scan Results ===\n");
        out.push_str(&format!("Interface: {}\n", result.interface));
        out.push_str(&format!(
            "Timestamp: {}\n",
            chrono::DateTime::from_timestamp(result.timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        ));
        out.push_str(&format!("Scan duration: {}ms\n", result.scan_duration_ms));
        out.push_str("\n");

        out.push_str("Summary:\n");
        out.push_str(&format!(
            "  Total networks: {}\n",
            result.summary.total_networks
        ));
        out.push_str(&format!(
            "  Strongest signal: {} dBm\n",
            result.summary.strongest_signal.unwrap_or(0)
        ));
        if let Some(avg) = result.summary.average_signal {
            out.push_str(&format!("  Average signal: {:.1} dBm\n", avg));
        }

        out.push_str("  By band:\n");
        for (band, count) in &result.summary.by_band {
            out.push_str(&format!("    {}: {}\n", band, count));
        }

        out.push_str("  By security:\n");
        for (sec, count) in &result.summary.by_security {
            out.push_str(&format!("    {}: {}\n", sec, count));
        }

        out.push_str("\nNetworks:\n");

        if result.networks.is_empty() {
            out.push_str("  No networks found\n");
            return out;
        }

        out.push_str(&format!(
            "{:<17} {:<32} {:>6} {:>4} {:<10} {:<12} {:<10} {}\n",
            "BSSID", "SSID", "SIGNAL", "CH", "BAND", "SECURITY", "QUALITY", "VENDOR"
        ));
        out.push_str(&format!(
            "{:<17} {:<32} {:>6} {:>4} {:<10} {:<12} {:<10} {}\n",
            "-----------------",
            "------------------------------",
            "------",
            "----",
            "----------",
            "------------",
            "----------",
            "------"
        ));

        for net in &result.networks {
            let ssid_display = if net.ssid.is_empty() {
                "<hidden>".to_string()
            } else {
                net.ssid.clone()
            };
            let ssid_truncated = if ssid_display.len() > 30 {
                format!("{}..", &ssid_display[..28])
            } else {
                ssid_display
            };

            out.push_str(&format!(
                "{:<17} {:<32} {:>5} dBm {:>4} {:<10} {:<12} {:>3}% {}\n",
                net.bssid,
                ssid_truncated,
                net.signal_dbm,
                net.channel,
                net.band,
                net.security,
                net.quality_percent,
                net.vendor.as_deref().unwrap_or("")
            ));
        }

        out
    }

    pub fn format_json(&self, result: &ScanResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(result)?)
    }

    pub fn format_csv(&self, result: &ScanResult) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(vec![]);

        wtr.write_record(&[
            "bssid",
            "ssid",
            "signal_dbm",
            "frequency_mhz",
            "channel",
            "band",
            "width",
            "security",
            "wps",
            "quality_percent",
            "noise_floor_dbm",
            "snr_db",
            "vendor",
            "last_seen",
        ])?;

        for net in &result.networks {
            wtr.write_record(&[
                &net.bssid,
                &net.ssid,
                &net.signal_dbm.to_string(),
                &net.frequency_mhz.to_string(),
                &net.channel.to_string(),
                &net.band,
                &net.width,
                &net.security,
                &net.wps.to_string(),
                &net.quality_percent.to_string(),
                &net.noise_floor_dbm
                    .map_or("".to_string(), |v| v.to_string()),
                &net.snr_db.map_or("".to_string(), |v| format!("{:.1}", v)),
                net.vendor.as_deref().unwrap_or(""),
                &net.last_seen.to_string(),
            ])?;
        }

        wtr.flush()?;
        Ok(String::from_utf8(wtr.into_inner()?)?)
    }

    pub fn format_analysis_text(&self, result: &AnalysisResult) -> String {
        let mut out = String::new();

        out.push_str("=== Channel Analysis ===\n");
        out.push_str(&format!("Interface: {}\n", result.interface));
        out.push_str(&format!("Duration: {}s\n", result.duration_secs));
        out.push_str(&format!(
            "Interference detected: {}\n",
            result.interference_detected
        ));
        out.push_str("\n");

        out.push_str(&format!(
            "{:<8} {:<12} {:>8} {:>8} {:>8} {:>8} {:>12} {:>12}\n",
            "CHANNEL", "BAND", "NETWORKS", "AVG SIG", "MAX SIG", "MIN SIG", "OVERLAP%", "UTIL%"
        ));

        for ch in &result.channels {
            out.push_str(&format!(
                "{:<8} {:<12} {:>8} {:>7.1} {:>7} {:>7} {:>11.1} {:>11}\n",
                ch.channel,
                ch.band,
                ch.networks,
                ch.avg_signal,
                ch.max_signal,
                ch.min_signal,
                ch.overlap_score,
                ch.utilization_percent
            ));
        }

        out.push_str("\nRecommendations:\n");
        for rec in &result.recommendations {
            out.push_str(&format!("  - {}\n", rec));
        }

        out
    }

    pub fn format_analysis_json(&self, result: &AnalysisResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(result)?)
    }

    pub fn format_analysis_csv(&self, result: &AnalysisResult) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(vec![]);

        wtr.write_record(&[
            "channel",
            "band",
            "networks",
            "avg_signal",
            "max_signal",
            "min_signal",
            "overlap_score",
            "utilization_percent",
        ])?;

        for ch in &result.channels {
            wtr.write_record(&[
                &ch.channel.to_string(),
                &ch.band,
                &ch.networks.to_string(),
                &format!("{:.1}", ch.avg_signal),
                &ch.max_signal.to_string(),
                &ch.min_signal.to_string(),
                &format!("{:.1}", ch.overlap_score),
                &ch.utilization_percent.to_string(),
            ])?;
        }

        wtr.flush()?;
        Ok(String::from_utf8(wtr.into_inner()?)?)
    }

    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        let expanded = shellexpand::tilde(path).to_string();
        if let Some(parent) = std::path::Path::new(&expanded).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&expanded, content).await?;
        Ok(())
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "wifiscan")]
#[command(
    about = "CLI WiFi scanner & signal analyzer - like iwlist + nmcli but with JSON/CSV output and continuous monitoring"
)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for WiFi networks (one-shot)
    Scan {
        /// Network interface to use (auto-detect if not specified)
        #[arg(short, long)]
        interface: Option<String>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,

        /// Filter by minimum signal strength (dBm, e.g., -70)
        #[arg(long)]
        min_signal: Option<i32>,

        /// Filter by band (2.4, 5, 6)
        #[arg(long, value_enum)]
        band: Option<BandFilter>,

        /// Filter by security type
        #[arg(long, value_enum)]
        security: Option<SecurityFilter>,

        /// Sort by (signal, ssid, channel, security)
        #[arg(long, default_value = "signal")]
        sort: SortBy,

        /// Show hidden networks
        #[arg(long)]
        show_hidden: bool,
    },

    /// Continuous monitoring mode
    Monitor {
        /// Network interface to use
        #[arg(short = 'I', long)]
        interface: Option<String>,

        /// Interval between scans (milliseconds)
        #[arg(short = 'i', long, default_value = "2000")]
        interval: u64,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,

        /// Number of scans (0 = infinite)
        #[arg(short, long, default_value = "0")]
        count: u32,

        /// Track specific BSSIDs only
        #[arg(long)]
        track: Vec<String>,
    },

    /// Show detailed info for a specific network
    Info {
        /// BSSID or SSID of the network
        network: String,

        /// Network interface
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// List available wireless interfaces
    Interfaces,

    /// Show channel utilization and interference analysis
    Analyze {
        /// Network interface
        #[arg(short = 'I', long)]
        interface: Option<String>,

        /// Duration to analyze (seconds)
        #[arg(short = 'D', long, default_value = "10")]
        duration: u64,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate config file
    Init {
        /// Config file path
        #[arg(short, long, default_value = "~/.config/wifiscan/config.toml")]
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = Config::load().await?;
    let scanner = create_scanner()?;
    let mut engine = ScanEngine::new(scanner);

    match cli.command {
        Commands::Scan {
            interface,
            format,
            output,
            min_signal,
            band,
            security,
            sort,
            show_hidden,
        } => {
            let scan_config = ScanConfig {
                interface,
                min_signal,
                band_filter: band,
                security_filter: security,
                sort_by: sort,
                show_hidden,
            };

            let result = engine.scan_once(scan_config).await?;
            let formatter = OutputFormatter::new(format);
            formatter.output(&result, output.as_deref()).await?;
        }

        Commands::Monitor {
            interface,
            interval,
            format,
            output,
            count,
            track,
        } => {
            let scan_config = ScanConfig {
                interface,
                min_signal: None,
                band_filter: None,
                security_filter: None,
                sort_by: SortBy::Signal,
                show_hidden: false,
            };

            engine
                .monitor(
                    scan_config,
                    Duration::from_millis(interval),
                    count,
                    track,
                    format,
                    output,
                )
                .await?;
        }

        Commands::Info { network, interface } => {
            let scan_config = ScanConfig {
                interface,
                min_signal: None,
                band_filter: None,
                security_filter: None,
                sort_by: SortBy::Signal,
                show_hidden: true,
            };

            let result = engine.scan_once(scan_config).await?;
            if let Some(net) = result
                .networks
                .iter()
                .find(|n| n.bssid == network || n.ssid == network)
            {
                println!("{}", serde_json::to_string_pretty(net)?);
            } else {
                eprintln!("Network not found: {}", network);
                std::process::exit(1);
            }
        }

        Commands::Interfaces => {
            let interfaces = engine.scanner.list_interfaces().await?;
            for iface in interfaces {
                println!("{} - {} ({})", iface.name, iface.description, iface.status);
            }
        }

        Commands::Analyze {
            interface,
            duration,
            format,
            output,
        } => {
            let analysis = engine
                .analyze(interface, Duration::from_secs(duration))
                .await?;
            let formatter = OutputFormatter::new(format);
            formatter
                .output_analysis(&analysis, output.as_deref())
                .await?;
        }

        Commands::Init { path } => {
            Config::create_default(&path).await?;
            println!("Created config at: {}", path);
        }
    }

    Ok(())
}
