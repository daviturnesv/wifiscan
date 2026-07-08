# wifiscan

CLI WiFi scanner & signal analyzer - like `iwlist` + `nmcli` but with JSON/CSV output and continuous monitoring.

## Features

- **One-shot scanning** - Quick scan for nearby WiFi networks
- **Continuous monitoring** - Track signal quality over time with configurable intervals
- **Channel analysis** - Detect interference and find optimal channels
- **Multiple output formats** - Text (human-readable), JSON (for automation), CSV (for spreadsheets)
- **Rich filtering** - Filter by signal strength, band (2.4/5/6 GHz), security type
- **Cross-platform** - Linux (via `iw`/`nmcli`), macOS (via `airport`), Windows (via `netsh`)

## Installation

### From Source (Rust)

```bash
git clone https://github.com/daviturnesv/wifiscan
cd wifiscan
cargo install --path .
```

### Pre-built Binaries

Download from [Releases](https://github.com/daviturnesv/wifiscan/releases).

## Usage

```bash
# Basic scan (default: text output)
wifiscan scan

# JSON output for automation
wifiscan scan --format json

# CSV output for spreadsheet analysis
wifiscan scan --format csv --output scan.csv

# Filter by signal strength (only networks stronger than -70 dBm)
wifiscan scan --min-signal -70

# Filter by band (5GHz only)
wifiscan scan --band 5

# Filter by security type
wifiscan scan --security wpa2

# Sort by channel instead of signal
wifiscan scan --sort channel

# Show hidden networks
wifiscan scan --show-hidden

# Continuous monitoring mode
wifiscan monitor --interval 2000

# Monitor with JSON output to file
wifiscan monitor --format json --output monitor.log

# Channel analysis (10 seconds)
wifiscan analyze --duration 10

# List available wireless interfaces
wifiscan interfaces

# Show detailed info for a specific network
wifiscan info <BSSID_or_SSID>

# Generate config file
wifiscan init
```

## Output Examples

### Text (default)

```
=== WiFi Scan Results ===
Interface: wlan0
Timestamp: 2026-07-07 15:30:45 UTC
Scan duration: 1234ms

Summary:
  Total networks: 12
  Strongest signal: -32 dBm
  Average signal: -58.5 dBm
  By band:
    2.4 GHz: 5
    5 GHz: 7
  By security:
    WPA2: 8
    WPA3: 3
    Open: 1

Networks:
BSSID             SSID                          SIGNAL CH   BAND      SECURITY   QUALITY VENDOR
----------------- ------------------------------ ------ ---- ---------- ---------- ------- ------
aa:bb:cc:dd:ee:ff MyNetwork                    -32 dBm   36 5 GHz      WPA3          95% 
11:22:33:44:55:66 GuestNetwork                 -45 dBm   6  2.4 GHz    WPA2          78% 
```

### JSON

```json
{
  "timestamp": 1720356645,
  "interface": "wlan0",
  "scan_duration_ms": 1234,
  "networks": [
    {
      "bssid": "aa:bb:cc:dd:ee:ff",
      "ssid": "MyNetwork",
      "signal_dbm": -32,
      "frequency_mhz": 5180,
      "channel": 36,
      "band": "5 GHz",
      "width": "80 MHz",
      "security": "WPA3",
      "security_flags": ["RSN", "SAE"],
      "wps": false,
      "rates": [],
      "vendor": null,
      "last_seen": 1720356645,
      "quality_percent": 95,
      "noise_floor_dbm": -95,
      "snr_db": 63.0
    }
  ],
  "summary": {
    "total_networks": 12,
    "by_band": {
      "5 GHz": 7,
      "2.4 GHz": 5
    },
    "by_security": {
      "WPA2": 8,
      "WPA3": 3,
      "Open": 1
    },
    "strongest_signal": -32,
    "average_signal": -58.5,
    "channel_utilization": {
      "36": 3,
      "6": 2,
      "1": 2
    }
  }
}
```

### CSV

```csv
bssid,ssid,signal_dbm,frequency_mhz,channel,band,width,security,wps,quality_percent,noise_floor_dbm,snr_db,vendor,last_seen
aa:bb:cc:dd:ee:ff,MyNetwork,-32,5180,36,5 GHz,80 MHz,WPA3,false,95,-95,63.0,,1720356645
```

## Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--interface` | `-i` | Target interface | auto-detect |
| `--format` | `-f` | Output format (text, json, csv) | text |
| `--output` | `-o` | Output file path | stdout |
| `--min-signal` | | Minimum signal (dBm) | -80 |
| `--band` | | Band filter (2.4, 5, 6) | all |
| `--security` | | Security filter (open, wep, wpa, wpa2, wpa3) | all |
| `--sort` | | Sort by (signal, ssid, channel, security) | signal |
| `--show-hidden` | | Show hidden networks | false |
| `--interval` | `-i` | Monitor interval (ms) | 2000 |
| `--count` | `-c` | Number of scans (0 = infinite) | 0 |
| `--track` | | Track specific BSSIDs | none |
| `--duration` | `-d` | Analysis duration (s) | 10 |

## Configuration

Generate a default config file:

```bash
wifiscan init
```

Config file location: `~/.config/wifiscan/config.toml`

```toml
default_interface = "wlan0"
default_format = "text"
default_interval_ms = 2000
default_min_signal = -80
scan_timeout_ms = 10000
```

## Requirements

- Linux: `iw` (recommended) or `nmcli` (NetworkManager)
- macOS: Built-in `airport` utility
- Windows: Built-in `netsh` (limited)

For best results on Linux, run with `sudo` to get complete scan data.

## Development

```bash
# Run tests
cargo test

# Build release
cargo build --release

# Lint
cargo clippy

# Format
cargo fmt
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and lint
5. Submit a PR