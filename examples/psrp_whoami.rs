//! Lab timing example: PowerShell `whoami` via real PSRP path.
//!
//! Usage:
//! ```bash
//! WINRM_HOST=10.10.50.10 WINRM_USER=rdp_user01 WINRM_PASS='...' \
//!   cargo run --example psrp_whoami --release
//! ```

use std::time::Instant;

use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("WINRM_HOST").unwrap_or_else(|_| "10.10.50.10".into());
    let user = std::env::var("WINRM_USER").unwrap_or_else(|_| "rdp_user01".into());
    let pass = std::env::var("WINRM_PASS").expect("set WINRM_PASS");
    let domain = std::env::var("WINRM_DOMAIN").unwrap_or_default();

    let client = WinrmClient::new(
        WinrmConfig::default(),
        WinrmCredentials::new(user, pass, domain),
    )?;

    let t = Instant::now();
    let out = client.run_powershell(&host, "whoami").await?;
    let elapsed = t.elapsed();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("exit_code={}", out.exit_code);
    println!("elapsed_ms={}", elapsed.as_millis());
    println!("elapsed_secs={:.3}", elapsed.as_secs_f64());
    println!("stdout={stdout}");
    if !stderr.is_empty() {
        eprintln!("stderr={stderr}");
    }

    if out.exit_code != 0 {
        std::process::exit(1);
    }
    Ok(())
}
