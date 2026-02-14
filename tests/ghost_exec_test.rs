use std::process::Command;
use std::fs;

#[test]
fn test_ghost_execution() {
    let test_vault = "/tmp/test_ghost_exec.db";

    // Cleanup
    let _ = fs::remove_file(test_vault);

    // Set vault path
    std::env::set_var("AK_VAULT_PATH", test_vault);

    // Initialize vault
    let init = Command::new("cargo")
        .args(&["run", "--", "init"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn init");

    let init_output = init.wait_with_output().expect("Failed to wait for init");

    // Add a test secret
    let add = Command::new("sh")
        .arg("-c")
        .arg("echo -e 'test_password\nmy_secret_value' | cargo run -- add test_key")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to add secret");

    assert!(add.status.success(), "Failed to add secret");

    // Test exec command
    let exec = Command::new("sh")
        .arg("-c")
        .arg("echo 'test_password' | cargo run -- exec --env MY_KEY=test_key -- printenv MY_KEY")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to exec");

    let output = String::from_utf8_lossy(&exec.stdout);
    assert!(output.contains("my_secret_value"), "Secret not injected into environment");

    // Cleanup
    let _ = fs::remove_file(test_vault);
}

#[test]
fn test_multiple_env_vars() {
    let test_vault = "/tmp/test_multi_env.db";

    // Cleanup
    let _ = fs::remove_file(test_vault);

    std::env::set_var("AK_VAULT_PATH", test_vault);

    // Initialize and add secrets
    Command::new("sh")
        .arg("-c")
        .arg("echo 'test_password' | cargo run -- init")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to init");

    Command::new("sh")
        .arg("-c")
        .arg("echo -e 'test_password\nvalue1' | cargo run -- add key1")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to add key1");

    Command::new("sh")
        .arg("-c")
        .arg("echo -e 'test_password\nvalue2' | cargo run -- add key2")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to add key2");

    // Test multiple env vars
    let exec = Command::new("sh")
        .arg("-c")
        .arg("echo 'test_password' | cargo run -- exec --env VAR1=key1 --env VAR2=key2 -- sh -c 'echo $VAR1:$VAR2'")
        .env("AK_VAULT_PATH", test_vault)
        .output()
        .expect("Failed to exec");

    let output = String::from_utf8_lossy(&exec.stdout);
    assert!(output.contains("value1:value2"), "Multiple secrets not injected correctly");

    // Cleanup
    let _ = fs::remove_file(test_vault);
}
