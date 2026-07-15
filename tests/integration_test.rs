use std::process::Command;
use std::fs;
use std::path::Path;

#[test]
fn test_basic_cli_execution() {
    // Proves the binary compiles and the CLI parser initializes correctly
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to execute cargo run");
        
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("qcrypt"));
}
