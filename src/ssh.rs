//! SSH bootstrap: connect to remote host, start mosh-server, extract key and port.
//!
//! Authentication order (mirrors OpenSSH):
//! 1. Explicit identity file (-i flag)
//! 2. SSH agent (Windows OpenSSH agent pipe → Pageant → SSH_AUTH_SOCK)
//! 3. Default key files (~/.ssh/id_ed25519, id_rsa, id_ecdsa)
//! 4. Interactive password prompt (stdin)
//!
//! Server key verification uses ~/.ssh/known_hosts (standard OpenSSH location).

use anyhow::{bail, Context, Result};
use russh::keys::key;
use russh::*;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

// Windows OpenSSH agent named pipe path.
const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Result of SSH bootstrap: port and encryption key.
#[derive(Debug)]
pub struct MoshSession {
    pub port: u16,
    pub key: String,
    pub remote_ip: String,
}

/// SSH client handler with known_hosts verification.
struct SshClient {
    host: String,
    port: u16,
    /// Set after check_server_key to indicate the key was new and should be learned.
    server_key_new: bool,
}

#[async_trait::async_trait]
impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let known_hosts_path = ssh_dir().join("known_hosts");

        // If known_hosts file exists, check it
        if known_hosts_path.exists() {
            match russh_keys::check_known_hosts_path(
                &self.host,
                self.port,
                server_public_key,
                &known_hosts_path,
            ) {
                Ok(true) => {
                    // Key matches — trusted
                    return Ok(true);
                }
                Ok(false) => {
                    // Host not in known_hosts — ask user to accept
                    let fingerprint = server_public_key.fingerprint();
                    eprintln!(
                        "The authenticity of host '{}:{}' can't be established.",
                        self.host, self.port
                    );
                    eprintln!(
                        "{} key fingerprint is {}.",
                        server_public_key.name(),
                        fingerprint
                    );

                    if confirm_prompt("Are you sure you want to continue connecting (yes/no)? ") {
                        // Learn the key
                        self.server_key_new = true;
                        if let Err(e) = russh_keys::known_hosts::learn_known_hosts_path(
                            &self.host,
                            self.port,
                            server_public_key,
                            &known_hosts_path,
                        ) {
                            eprintln!("Warning: failed to save host key: {}", e);
                        } else {
                            eprintln!(
                                "Warning: Permanently added '{}:{}' to the list of known hosts.",
                                self.host, self.port
                            );
                        }
                        return Ok(true);
                    } else {
                        eprintln!("Host key verification failed.");
                        return Ok(false);
                    }
                }
                Err(russh_keys::Error::KeyChanged { line }) => {
                    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
                    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
                    eprintln!(
                        "The {} host key for '{}' has changed (line {} of {:?}).",
                        server_public_key.name(),
                        self.host,
                        line,
                        known_hosts_path
                    );
                    eprintln!("Host key verification failed.");
                    return Ok(false);
                }
                Err(e) => {
                    eprintln!("Warning: error reading known_hosts: {}", e);
                    // Fall through to the "no file" path below
                }
            }
        }

        // No known_hosts file — first connection, ask user
        let fingerprint = server_public_key.fingerprint();
        eprintln!(
            "The authenticity of host '{}:{}' can't be established.",
            self.host, self.port
        );
        eprintln!(
            "{} key fingerprint is {}.",
            server_public_key.name(),
            fingerprint
        );

        if confirm_prompt("Are you sure you want to continue connecting (yes/no)? ") {
            // Ensure ~/.ssh directory exists
            let ssh_dir = ssh_dir();
            if !ssh_dir.exists() {
                let _ = std::fs::create_dir_all(&ssh_dir);
            }

            self.server_key_new = true;
            if let Err(e) = russh_keys::known_hosts::learn_known_hosts_path(
                &self.host,
                self.port,
                server_public_key,
                &known_hosts_path,
            ) {
                eprintln!("Warning: failed to save host key: {}", e);
            } else {
                eprintln!(
                    "Warning: Permanently added '{}:{}' to the list of known hosts.",
                    self.host, self.port
                );
            }
            Ok(true)
        } else {
            eprintln!("Host key verification failed.");
            Ok(false)
        }
    }
}

/// Configuration for the SSH connection.
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub mosh_server_command: String,
    pub mosh_server_args: Vec<String>,
}

impl SshConfig {
    pub fn new(host: &str, username: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 22,
            username: username.to_string(),
            password: None,
            identity_file: None,
            mosh_server_command: "mosh-server".to_string(),
            mosh_server_args: vec![
                "new".to_string(),
                "-s".to_string(),
                "-c".to_string(),
                "256".to_string(),
                "-l".to_string(),
                "LANG=en_US.UTF-8".to_string(),
            ],
        }
    }

    /// Set SSH port (default: 22).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set password for authentication.
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set identity file (private key) for authentication.
    pub fn with_identity_file(mut self, path: PathBuf) -> Self {
        self.identity_file = Some(path);
        self
    }
}

/// Connect via SSH and start mosh-server, returning the connection details.
pub async fn bootstrap(config: &SshConfig) -> Result<MoshSession> {
    let ssh_config = russh::client::Config::default();
    let sh = SshClient {
        host: config.host.clone(),
        port: config.port,
        server_key_new: false,
    };

    eprintln!(
        "SSH: connecting to {}@{}:{}",
        config.username, config.host, config.port
    );

    let mut session = russh::client::connect(
        Arc::new(ssh_config),
        (config.host.as_str(), config.port),
        sh,
    )
    .await
    .context("SSH connection failed")?;

    // ── Authentication ──────────────────────────────────────────────────

    let authenticated = authenticate(&mut session, config).await?;

    if !authenticated {
        bail!(
            "SSH authentication failed for {}@{}",
            config.username,
            config.host
        );
    }

    eprintln!("SSH: authenticated successfully");

    // ── Execute mosh-server ─────────────────────────────────────────────

    let server_cmd = format!(
        "{} {}",
        config.mosh_server_command,
        config.mosh_server_args.join(" ")
    );

    log::info!("SSH: executing: {}", server_cmd);

    let mut channel = session
        .channel_open_session()
        .await
        .context("Failed to open SSH channel")?;

    channel
        .exec(true, server_cmd.as_str())
        .await
        .context("Failed to execute mosh-server command")?;

    // Collect output
    let mut stdout_data = Vec::new();
    let mut stderr_data = Vec::new();

    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };

        match msg {
            ChannelMsg::Data { ref data } => {
                stdout_data.extend_from_slice(data);
            }
            ChannelMsg::ExtendedData { ref data, ext } => {
                if ext == 1 {
                    stderr_data.extend_from_slice(data);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    let stderr_str = String::from_utf8_lossy(&stderr_data);
                    bail!(
                        "mosh-server exited with status {}: {}",
                        exit_status,
                        stderr_str
                    );
                }
            }
            ChannelMsg::Eof => break,
            _ => {}
        }
    }

    // Parse the MOSH CONNECT line from stdout
    let stdout_str = String::from_utf8_lossy(&stdout_data);
    let session_info = parse_mosh_connect(&stdout_str).context(
        "Failed to parse MOSH CONNECT response from mosh-server. \
         Is mosh-server installed on the remote host?",
    )?;

    // Disconnect SSH
    let _ = session
        .disconnect(Disconnect::ByApplication, "mosh session started", "en")
        .await;

    Ok(MoshSession {
        port: session_info.0,
        key: session_info.1,
        remote_ip: config.host.clone(),
    })
}

// ── Authentication strategies ───────────────────────────────────────────────

/// Try all authentication methods in order. Returns true on success.
async fn authenticate(
    session: &mut client::Handle<SshClient>,
    config: &SshConfig,
) -> Result<bool> {
    // 1. Explicit identity file (if -i was given)
    if let Some(ref identity_path) = config.identity_file {
        eprintln!("SSH: trying identity file {:?}", identity_path);
        match try_key_file(session, &config.username, identity_path).await {
            Ok(true) => return Ok(true),
            Ok(false) => eprintln!("SSH: key file rejected by server"),
            Err(e) => eprintln!("SSH: failed to load key file: {}", e),
        }
    }

    // 2. Explicit password (if --password was given)
    if let Some(ref password) = config.password {
        eprintln!("SSH: trying password authentication");
        match session
            .authenticate_password(&config.username, password.as_str())
            .await
        {
            Ok(true) => return Ok(true),
            Ok(false) => eprintln!("SSH: password rejected by server"),
            Err(e) => eprintln!("SSH: password auth error: {}", e),
        }
    }

    // 3. SSH agent (Windows OpenSSH → Pageant → SSH_AUTH_SOCK)
    match try_ssh_agent(session, &config.username).await {
        Ok(true) => return Ok(true),
        Ok(false) => {} // Agent had no usable keys, continue silently
        Err(e) => log::debug!("SSH agent auth failed: {}", e),
    }

    // 4. Default key files
    let ssh_dir = ssh_dir();
    let key_names = ["id_ed25519", "id_rsa", "id_ecdsa"];
    for name in &key_names {
        let key_path = ssh_dir.join(name);
        if key_path.exists() {
            eprintln!("SSH: trying key {}", key_path.display());
            match try_key_file(session, &config.username, &key_path).await {
                Ok(true) => return Ok(true),
                Ok(false) => eprintln!("SSH: key {} rejected by server", name),
                Err(e) => eprintln!("SSH: failed to load {}: {}", name, e),
            }
        }
    }

    // 5. Interactive password prompt (only if stdin is a terminal)
    if atty_stdin() && config.password.is_none() {
        for attempt in 1..=3 {
            let prompt = format!("{}@{}'s password: ", config.username, config.host);
            match read_password(&prompt) {
                Some(password) if !password.is_empty() => {
                    match session
                        .authenticate_password(&config.username, password.as_str())
                        .await
                    {
                        Ok(true) => return Ok(true),
                        Ok(false) => {
                            if attempt < 3 {
                                eprintln!("Permission denied, please try again.");
                            }
                        }
                        Err(e) => {
                            eprintln!("SSH: password auth error: {}", e);
                            break;
                        }
                    }
                }
                _ => break, // Empty password or read error
            }
        }
    }

    Ok(false)
}

/// Try authenticating with a key file.
async fn try_key_file(
    session: &mut client::Handle<SshClient>,
    username: &str,
    path: &std::path::Path,
) -> Result<bool> {
    // Try loading without passphrase first
    let key_pair = match russh_keys::load_secret_key(path, None) {
        Ok(kp) => kp,
        Err(initial_err) => {
            let err_str = initial_err.to_string();
            let is_encrypted = err_str.contains("encrypted")
                || err_str.contains("Encrypted")
                || err_str.contains("passphrase");

            if !is_encrypted {
                // Not an encryption issue — unsupported format, corrupt, etc.
                bail!("Failed to load key '{}': {}", path.display(), initial_err);
            }

            // Key is encrypted — prompt for passphrase (3 attempts, like OpenSSH)
            if !atty_stdin() {
                bail!(
                    "Key '{}' is encrypted and no terminal for passphrase prompt",
                    path.display()
                );
            }

            let mut loaded = None;
            for attempt in 1..=3 {
                let prompt = format!("Enter passphrase for key '{}': ", path.display());
                match read_password(&prompt) {
                    Some(passphrase) if !passphrase.is_empty() => {
                        match russh_keys::load_secret_key(path, Some(&passphrase)) {
                            Ok(kp) => {
                                loaded = Some(kp);
                                break;
                            }
                            Err(e) => {
                                let msg = friendly_key_error(&e);
                                if attempt < 3 {
                                    eprintln!("{}", msg);
                                } else {
                                    bail!(
                                        "Failed to load key '{}' after 3 attempts: {}",
                                        path.display(),
                                        msg
                                    );
                                }
                            }
                        }
                    }
                    _ => {
                        // Empty passphrase or read error — give up on this key
                        bail!("No passphrase provided for '{}'", path.display());
                    }
                }
            }

            loaded.unwrap() // safe: loop either sets `loaded` or bails
        }
    };

    let result = session
        .authenticate_publickey(username, Arc::new(key_pair))
        .await?;
    Ok(result)
}

/// Try authenticating via SSH agent (Windows OpenSSH pipe, Pageant, or SSH_AUTH_SOCK).
async fn try_ssh_agent(
    session: &mut client::Handle<SshClient>,
    username: &str,
) -> Result<bool> {
    // Try Windows OpenSSH agent (named pipe)
    match try_openssh_agent().await {
        Ok(agent) => {
            eprintln!("SSH: trying Windows OpenSSH agent");
            return try_agent_auth(session, username, agent).await;
        }
        Err(e) => {
            eprintln!(
                "SSH: Windows OpenSSH agent not available ({})\n  \
                 Hint: start it with: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
                e
            );
        }
    }

    // Try Pageant (PuTTY agent).
    // The `pageant` crate panics (unwrap) if Pageant isn't running, so we
    // MUST check that the Pageant window exists before calling connect_pageant().
    if is_pageant_running() {
        eprintln!("SSH: trying Pageant agent");
        let agent = russh_keys::agent::client::AgentClient::connect_pageant().await;
        match try_agent_auth(session, username, agent).await {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => log::debug!("Pageant auth failed: {}", e),
        }
    }

    // SSH_AUTH_SOCK is not available on native Windows (Unix sockets only).
    // The Windows OpenSSH agent and Pageant paths above cover Windows agents.

    Ok(false)
}

/// Try to connect to the Windows OpenSSH agent named pipe.
async fn try_openssh_agent(
) -> Result<russh_keys::agent::client::AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>>
{
    let agent =
        russh_keys::agent::client::AgentClient::connect_named_pipe(OPENSSH_AGENT_PIPE).await?;
    Ok(agent)
}

/// Authenticate using an SSH agent by trying each key the agent offers.
async fn try_agent_auth<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    session: &mut client::Handle<SshClient>,
    username: &str,
    mut agent: russh_keys::agent::client::AgentClient<S>,
) -> Result<bool> {
    let identities = agent.request_identities().await?;
    if identities.is_empty() {
        return Ok(false);
    }

    eprintln!("SSH: agent has {} key(s)", identities.len());

    for identity in identities {
        log::debug!("SSH: trying agent key: {}", identity.name());
        let (returned_agent, auth_result) = session
            .authenticate_future(username, identity, agent)
            .await;
        agent = returned_agent;
        match auth_result {
            Ok(true) => return Ok(true),
            Ok(false) => continue,
            Err(e) => {
                log::debug!("SSH: agent key failed: {}", e);
                continue;
            }
        }
    }

    Ok(false)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Translate cryptic russh_keys errors into human-readable messages.
fn friendly_key_error(e: &russh_keys::Error) -> String {
    let raw = e.to_string();
    if raw.contains("Unpad") || raw.contains("unpad") || raw.contains("padding") {
        format!(
            "Decryption failed ({}). Wrong passphrase, or key format not \
             supported by russh.\n  \
             Workaround: load the key into the Windows OpenSSH agent instead:\n    \
             ssh-add {}\n  \
             Or convert to modern format:\n    \
             ssh-keygen -p -o -f <keyfile>",
            raw, "<keyfile>"
        )
    } else if raw.contains("encrypted") || raw.contains("Encrypted") {
        "Key is encrypted — passphrase required.".to_string()
    } else if raw.contains("format") || raw.contains("Format") || raw.contains("parse") {
        format!("Unsupported key format: {}", raw)
    } else {
        raw
    }
}

/// Parse the "MOSH CONNECT <port> <key>" line from mosh-server output.
fn parse_mosh_connect(output: &str) -> Result<(u16, String)> {
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("MOSH CONNECT ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let port: u16 = parts[2]
                    .parse()
                    .context("Invalid port in MOSH CONNECT")?;
                let key = parts[3].to_string();
                return Ok((port, key));
            }
        }
    }
    bail!(
        "No 'MOSH CONNECT' line found in mosh-server output:\n{}",
        output
    )
}

/// Check if PuTTY's Pageant is running by looking for its window.
fn is_pageant_running() -> bool {
    unsafe {
        let class_name = b"Pageant\0";
        let window_name = b"Pageant\0";
        let hwnd = windows_sys::Win32::UI::WindowsAndMessaging::FindWindowA(
            class_name.as_ptr(),
            window_name.as_ptr(),
        );
        !hwnd.is_null()
    }
}

/// Get the user's ~/.ssh directory (using the correct Windows path).
fn ssh_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh")
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// Check if stdin is a terminal (for interactive prompts).
fn atty_stdin() -> bool {
    use std::os::windows::io::AsRawHandle;
    let handle = std::io::stdin().as_raw_handle() as *mut core::ffi::c_void;
    // GetConsoleMode succeeds only for console handles
    let mut mode: u32 = 0;
    unsafe {
        windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) != 0
    }
}

/// Prompt the user for a yes/no confirmation. Returns true if "yes".
fn confirm_prompt(prompt: &str) -> bool {
    if !atty_stdin() {
        // Non-interactive: reject by default (safe)
        return false;
    }
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let answer = input.trim().to_lowercase();
        answer == "yes" || answer == "y"
    } else {
        false
    }
}

/// Read a password from the terminal with echo disabled.
fn read_password(prompt: &str) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::*;

    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();

    let stdin_handle = std::io::stdin().as_raw_handle() as *mut core::ffi::c_void;

    // Save current console mode
    let mut old_mode: u32 = 0;
    unsafe {
        if GetConsoleMode(stdin_handle, &mut old_mode) == 0 {
            // Not a console — can't disable echo
            return None;
        }
        // Disable echo, enable line input
        let new_mode = (old_mode & !ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        SetConsoleMode(stdin_handle, new_mode);
    }

    let mut password = String::new();
    let result = std::io::stdin().read_line(&mut password);

    // Restore console mode
    unsafe {
        SetConsoleMode(stdin_handle, old_mode);
    }
    eprintln!(); // Print newline after hidden input

    match result {
        Ok(_) => Some(password.trim_end_matches(&['\r', '\n'][..]).to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mosh_connect() {
        let output = "\n\nMOSH CONNECT 60001 AbCdEfGhIjKlMnOpQrStUv\n\n";
        let (port, key) = parse_mosh_connect(output).unwrap();
        assert_eq!(port, 60001);
        assert_eq!(key, "AbCdEfGhIjKlMnOpQrStUv");
    }

    #[test]
    fn test_parse_mosh_connect_with_noise() {
        let output = "Some debug output\nWarning: something\n\nMOSH CONNECT 60042 AAAAAAAAAAAAAAAAAAAAAA\nmore stuff";
        let (port, key) = parse_mosh_connect(output).unwrap();
        assert_eq!(port, 60042);
        assert_eq!(key, "AAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn test_parse_mosh_connect_missing() {
        let output = "no connect line here\n";
        assert!(parse_mosh_connect(output).is_err());
    }

    #[test]
    fn test_ssh_dir() {
        let dir = ssh_dir();
        assert!(dir.to_string_lossy().contains(".ssh"));
    }
}
