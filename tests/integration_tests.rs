use anyhow::Result;
use std::process::Command;

#[test]
fn test_help_output() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wifiscan"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("monitor"));
    assert!(stdout.contains("analyze"));
}

#[test]
fn test_scan_subcommand_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("interface"));
    assert!(stdout.contains("format"));
    assert!(stdout.contains("min-signal"));
}

#[test]
fn test_monitor_subcommand_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "monitor", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("interval"));
    assert!(stdout.contains("count"));
    assert!(stdout.contains("track"));
}

#[test]
fn test_interfaces_subcommand_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "interfaces", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
}

#[test]
fn test_analyze_subcommand_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "analyze", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("duration"));
    assert!(stdout.contains("format"));
}

#[test]
fn test_init_subcommand_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "init", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
}

#[test]
fn test_invalid_subcommand() {
    let output = Command::new("cargo")
        .args(["run", "--", "invalid"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(!output.status.success());
}

#[test]
fn test_version_flag() {
    let output = Command::new("cargo")
        .args(["run", "--", "--version"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0.1.0"));
}
