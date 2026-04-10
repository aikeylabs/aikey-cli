//! AiKeyLabs AK - Secure local-first secret management
//!
//! This library provides the core functionality for the AK CLI tool.

pub mod crypto;
pub mod storage;
pub mod synapse;
pub mod executor;
pub mod audit;
pub mod ratelimit;
pub mod config;
pub mod env_resolver;
pub mod env_renderer;
pub mod commands_project;
pub mod json_output;
pub mod global_config;
pub mod error_codes;
pub mod providers;
pub mod resolver;
pub mod events;
pub mod observability;
pub mod platform_client;
pub mod commands_account;
pub mod commands_proxy;
pub mod session;
pub mod ui_frame;
pub mod proxy_env;
pub mod profile_activation;

/// Prompts for a hidden input (password / API key), showing a `*` for each
/// keystroke in real time. Supports backspace and handles paste gracefully.
///
/// Falls back to `rpassword::read_password()` on non-Unix or if termios fails.
pub fn prompt_hidden(prompt: &str) -> std::io::Result<String> {
    use std::io::Write;
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();

    #[cfg(unix)]
    {
        if let Ok(value) = read_password_with_stars() {
            eprintln!(); // newline after the stars
            return Ok(value);
        }
    }

    // Fallback: silent read (no stars).
    let value = rpassword::read_password()?;
    eprintln!();
    Ok(value)
}

/// Unix-only: reads a password character by character with echo disabled,
/// printing `*` for each visible character. Supports backspace.
#[cfg(unix)]
fn read_password_with_stars() -> std::io::Result<String> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    // We read from /dev/tty so this works even when stdin is redirected.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();

    // Save original terminal settings.
    let orig = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(tty_fd, &mut t) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        t
    };

    // Disable echo + canonical mode (character-at-a-time).
    let mut raw = orig;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    unsafe {
        if libc::tcsetattr(tty_fd, libc::TCSANOW, &raw) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let mut password = String::new();
    let mut buf = [0u8; 1];

    loop {
        let n = (&tty).read(&mut buf)?;
        if n == 0 {
            break;
        }
        match buf[0] {
            // Enter (LF or CR)
            b'\n' | b'\r' => break,
            // Backspace or DEL
            0x7f | 0x08 => {
                if !password.is_empty() {
                    password.pop();
                    eprint!("\x08 \x08");
                    let _ = std::io::stderr().flush();
                }
            }
            // Ctrl-C → abort
            0x03 => {
                unsafe { libc::tcsetattr(tty_fd, libc::TCSANOW, &orig); }
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted"));
            }
            // Printable character (or pasted text byte)
            c => {
                password.push(c as char);
                eprint!("*");
                let _ = std::io::stderr().flush();
            }
        }
    }

    // Restore original terminal settings.
    unsafe { libc::tcsetattr(tty_fd, libc::TCSANOW, &orig); }

    Ok(password)
}
