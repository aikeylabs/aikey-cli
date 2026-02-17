use std::process::Command;
use std::fs;
use std::path::Path;

#[test]
fn test_ghost_execution() {
    let test_vault = "/tmp/test_ghost_exec.db";

    // Cleanup - handle both files and directories
    if Path::new(test_vault).is_dir() {
        let _ = fs::remove_dir_all(test_vault);
    } else {
        let _ = fs::remove_file(test_vault);
        let _ = fs::remove_file(format!("{}-shm", test_vault));
        let _ = fs::remove_file(format!("{}-wal", test_vault));
    }

    // Initialize vault
    let init = Command::new("cargo")
        .args(&["run", "--", "init"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .output()
        .expect("Failed to init");

    if !init.status.success() {
        eprintln!("Init stdout: {}", String::from_utf8_lossy(&init.stdout));
        eprintln!("Init stderr: {}", String::from_utf8_lossy(&init.stderr));
    }
    assert!(init.status.success(), "Failed to initialize vault");

    // Add a test secret
    let add = Command::new("cargo")
        .args(&["run", "--", "add", "test_key"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .env("AK_TEST_SECRET", "my_secret_value")
        .output()
        .expect("Failed to add secret");

    if !add.status.success() {
        eprintln!("Add stdout: {}", String::from_utf8_lossy(&add.stdout));
        eprintln!("Add stderr: {}", String::from_utf8_lossy(&add.stderr));
    }
    assert!(add.status.success(), "Failed to add secret");

    // Test exec command
    let exec = Command::new("cargo")
        .args(&["run", "--", "exec", "--env", "MY_KEY=test_key", "--", "printenv", "MY_KEY"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .output()
        .expect("Failed to exec");

    let output = String::from_utf8_lossy(&exec.stdout);
    if !output.contains("my_secret_value") {
        eprintln!("Exec stdout: {}", output);
        eprintln!("Exec stderr: {}", String::from_utf8_lossy(&exec.stderr));
    }
    assert!(output.contains("my_secret_value"), "Secret not injected into environment");

    // Cleanup
    if Path::new(test_vault).is_dir() {
        let _ = fs::remove_dir_all(test_vault);
    } else {
        let _ = fs::remove_file(test_vault);
        let _ = fs::remove_file(format!("{}-shm", test_vault));
        let _ = fs::remove_file(format!("{}-wal", test_vault));
    }
}

#[test]
fn test_multiple_env_vars() {
    let test_vault = "/tmp/test_multi_env.db";

    // Cleanup - handle both files and directories
    if Path::new(test_vault).is_dir() {
        let _ = fs::remove_dir_all(test_vault);
    } else {
        let _ = fs::remove_file(test_vault);
        let _ = fs::remove_file(format!("{}-shm", test_vault));
        let _ = fs::remove_file(format!("{}-wal", test_vault));
    }

    // Initialize vault
    Command::new("cargo")
        .args(&["run", "--", "init"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .output()
        .expect("Failed to init");

    // Add first secret
    Command::new("cargo")
        .args(&["run", "--", "add", "key1"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .env("AK_TEST_SECRET", "value1")
        .output()
        .expect("Failed to add key1");

    // Add second secret
    Command::new("cargo")
        .args(&["run", "--", "add", "key2"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .env("AK_TEST_SECRET", "value2")
        .output()
        .expect("Failed to add key2");

    // Test multiple env vars
    let exec = Command::new("cargo")
        .args(&["run", "--", "exec", "--env", "VAR1=key1", "--env", "VAR2=key2", "--", "sh", "-c", "echo $VAR1:$VAR2"])
        .env("AK_VAULT_PATH", test_vault)
        .env("AK_TEST_PASSWORD", "test_password")
        .output()
        .expect("Failed to exec");

    let output = String::from_utf8_lossy(&exec.stdout);
    if !output.contains("value1:value2") {
        eprintln!("Exec stdout: {}", output);
        eprintln!("Exec stderr: {}", String::from_utf8_lossy(&exec.stderr));
    }
    assert!(output.contains("value1:value2"), "Multiple secrets not injected correctly");

    // Cleanup
    if Path::new(test_vault).is_dir() {
        let _ = fs::remove_dir_all(test_vault);
    } else {
        let _ = fs::remove_file(test_vault);
        let _ = fs::remove_file(format!("{}-shm", test_vault));
        let _ = fs::remove_file(format!("{}-wal", test_vault));
    }
}
