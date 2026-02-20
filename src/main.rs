//! Mosh client for Windows — a native Rust implementation.
//!
//! Usage:
//!   mosh-client [OPTIONS] [user@]host [-- mosh-server-args...]
//!
//! This client:
//! 1. Bootstraps via SSH to start mosh-server on the remote host
//! 2. Establishes an encrypted UDP session using the Mosh protocol (SSP)
//! 3. Renders terminal output natively using the Windows Console API
//! 4. Provides predictive local echo for low-latency interaction

mod crypto;
mod network;
mod prediction;
mod renderer;
mod ssh;
mod terminal;
mod transport;
mod userstream;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use prediction::PredictionMode;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const MOSH_COMMAND_KEY: u8 = 0x1E; // Ctrl-^

/// Mosh client for Windows — a native Rust implementation of the Mobile Shell client.
#[derive(Parser, Debug)]
#[command(name = "mosh-client", version, about)]
struct Cli {
    /// Remote host in [user@]host format.
    #[arg(value_name = "HOST")]
    host: String,

    /// SSH port (default: 22).
    #[arg(short = 'p', long, default_value = "22")]
    ssh_port: u16,

    /// SSH identity file (private key).
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// SSH password (if not using key-based auth).
    /// WARNING: Visible in process list. Prefer key-based auth.
    #[arg(long)]
    password: Option<String>,

    /// Path to mosh-server on the remote host.
    #[arg(long, default_value = "mosh-server")]
    server: String,

    /// Prediction mode: always, adaptive, never.
    #[arg(long, default_value = "adaptive")]
    predict: String,

    /// Connect directly to a running mosh-server (skip SSH bootstrap).
    /// Format: IP:PORT with MOSH_KEY environment variable set.
    #[arg(long)]
    direct: Option<String>,

    /// Extra arguments to pass to mosh-server (after --).
    #[arg(last = true)]
    server_args: Vec<String>,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    // Parse prediction mode
    let predict_mode = match cli.predict.as_str() {
        "always" => PredictionMode::Always,
        "never" => PredictionMode::Never,
        "adaptive" | _ => PredictionMode::Adaptive,
    };

    // Get connection details either via SSH bootstrap or direct connection
    let (remote_addr, key_str) = if let Some(ref direct) = cli.direct {
        // Direct connection mode: MOSH_KEY must be set
        let key = std::env::var("MOSH_KEY")
            .context("MOSH_KEY environment variable must be set for direct connection")?;
        // Security: remove from env after reading
        unsafe { std::env::remove_var("MOSH_KEY") };
        let addr: SocketAddr = direct
            .parse()
            .context("Invalid direct address format (expected IP:PORT)")?;
        (addr, key)
    } else {
        // SSH bootstrap mode
        let (username, hostname) = parse_user_host(&cli.host);

        let mut ssh_config = ssh::SshConfig::new(&hostname, &username);
        ssh_config = ssh_config.with_port(cli.ssh_port);

        if let Some(ref password) = cli.password {
            ssh_config = ssh_config.with_password(password);
        }

        if let Some(ref identity) = cli.identity {
            ssh_config = ssh_config.with_identity_file(identity.clone());
        }

        ssh_config.mosh_server_command = cli.server.clone();

        if !cli.server_args.is_empty() {
            ssh_config.mosh_server_args = cli.server_args.clone();
        }

        eprintln!("Connecting to {} via SSH...", hostname);
        let session = ssh::bootstrap(&ssh_config).await?;
        eprintln!(
            "mosh-server started on port {}. Establishing UDP session...",
            session.port
        );

        // Resolve remote address
        let addr_str = format!("{}:{}", session.remote_ip, session.port);
        let addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .context("Failed to resolve remote address")?;

        (addr, session.key)
    };

    // Parse the encryption key
    let key = crypto::Base64Key::from_str(&key_str)?;

    // Enter the main session
    run_session(remote_addr, &key, predict_mode).await
}

/// Parse "[user@]host" into (username, hostname).
fn parse_user_host(input: &str) -> (String, String) {
    if let Some(at_pos) = input.find('@') {
        let user = input[..at_pos].to_string();
        let host = input[at_pos + 1..].to_string();
        (user, host)
    } else {
        // Default to current user
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "root".to_string());
        (user, input.to_string())
    }
}

/// Main session loop: manages the terminal, transport, and rendering.
async fn run_session(
    remote_addr: SocketAddr,
    key: &crypto::Base64Key,
    predict_mode: PredictionMode,
) -> Result<()> {
    // Get terminal dimensions
    let (term_width, term_height) = crossterm::terminal::size().context("Failed to get terminal size")?;
    let width = term_width as usize;
    let height = term_height as usize;

    // Initialize the transport
    let mut transport = transport::Transport::new(
        key,
        remote_addr,
        crypto::Direction::ToServer,
        width,
        height,
    )
    .await?;

    log::info!(
        "UDP socket bound to {}, connecting to {}",
        transport.local_addr()?,
        remote_addr
    );

    // Latest modeled remote terminal state (transport-owned queue source).
    let mut latest_remote_fb = transport.latest_remote_framebuffer().clone();
    // Last framebuffer shown to user (authoritative remote + local overlays).
    let mut local_framebuffer: terminal::Framebuffer;

    // Initialize the renderer
    renderer::Renderer::init()?;
    let mut render = renderer::Renderer::new(width, height);
    let mut notification = renderer::NotificationBar::new();

    // Initialize prediction engine
    let mut predictor = prediction::PredictionEngine::new(predict_mode, width, height);

    // Send initial resize to server
    transport.push_resize(width as i32, height as i32);

    // Guard to ensure cleanup on exit
    let _cleanup = CleanupGuard;

    notification.set_message("mosh: Connecting...");

    // Main event loop
    let render_interval = Duration::from_millis(16); // ~60fps max
    let mut last_render = std::time::Instant::now();
    let mut command_pending = false;

    loop {
        // 1. Try to receive from network and update modeled remote state queue.
        transport.drain_recv()?;
        if transport.take_remote_state_changed() {
            latest_remote_fb = transport.latest_remote_framebuffer().clone();
            notification.clear();
        }
        if let Some(reason) = transport.remote_close_reason() {
            let _ = renderer::Renderer::cleanup();
            eprintln!("\nmosh: {}", reason);
            return Ok(());
        }
        predictor.set_local_frame_acked(transport.acked_state_num());
        predictor.set_send_interval(transport.send_interval_ms());
        predictor.set_local_frame_late_acked(transport.latest_remote_echo_ack());
        predictor.cull(&latest_remote_fb);

        // Update connection status notification
        if transport.time_since_last_recv() > Duration::from_secs(15) {
            notification.set_message(&format!(
                "mosh: Last contact {:.0}s ago",
                transport.time_since_last_recv().as_secs_f64()
            ));
        } else if !transport.has_received_data() {
            notification.set_message("mosh: Connecting...");
        }

        // Maintain the same local modeled framebuffer that upstream mosh uses
        // as the base for new prediction bytes.
        {
            let mut composed = latest_remote_fb.clone();
            if let Some((pr, pc)) = predictor.apply_overlays(&mut composed) {
                composed.cursor_row = pr;
                composed.cursor_col = pc;
            }
            local_framebuffer = composed;
        }

        // 2. Process user input (keyboard events)
        while event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key_event) => {
                    if !matches!(key_event.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    if transport.shutdown_in_progress() {
                        continue;
                    }
                    predictor.set_local_frame_sent(transport.sent_state_last_num());

                    if is_command_key(&key_event) {
                        if command_pending {
                            command_pending = false;
                            let data = vec![MOSH_COMMAND_KEY];
                            transport.push_user_input(&data);
                            predictor.new_user_input_batch(&data, &local_framebuffer);
                            notification.clear();
                        } else {
                            command_pending = true;
                            notification.set_message(
                                "mosh: commands: Ctrl-Z suspend, '.' quit, '^' literal Ctrl-^",
                            );
                        }
                        continue;
                    }

                    if command_pending {
                        command_pending = false;
                        let Some(data) = handle_key_event(&key_event) else {
                            notification.clear();
                            continue;
                        };

                        if data == b"." {
                            if !transport.shutdown_in_progress() {
                                notification.set_message("mosh: exiting on user request...");
                                transport.start_shutdown();
                            }
                            continue;
                        }

                        if data == vec![0x1a] {
                            // Upstream suspends via SIGSTOP; no direct equivalent on Windows.
                            notification.set_message("mosh: suspend is not supported on this platform");
                            continue;
                        }

                        let mut out = Vec::with_capacity(1 + data.len());
                        out.push(MOSH_COMMAND_KEY);
                        if data != b"^" {
                            out.extend_from_slice(&data);
                        }
                        transport.push_user_input(&out);
                        predictor.new_user_input_batch(&out, &local_framebuffer);
                        continue;
                    }

                    if let Some(data) = handle_key_event(&key_event) {
                        transport.push_user_input(&data);
                        predictor.new_user_input_batch(&data, &local_framebuffer);
                    }
                }
                Event::Paste(text) => {
                    if transport.shutdown_in_progress() {
                        continue;
                    }
                    if command_pending {
                        command_pending = false;
                        notification.set_message("mosh: command canceled");
                    }
                    predictor.set_local_frame_sent(transport.sent_state_last_num());
                    let data = text.into_bytes();
                    if !data.is_empty() {
                        transport.push_user_input(&data);
                        predictor.new_user_input_batch(&data, &local_framebuffer);
                    }
                }
                Event::Resize(new_w, new_h) => {
                    let w = new_w as usize;
                    let h = new_h as usize;
                    latest_remote_fb.resize(w, h);
                    local_framebuffer.resize(w, h);
                    render.resize(w, h);
                    predictor.resize(w, h);
                    if !transport.shutdown_in_progress() {
                        transport.push_resize(w as i32, h as i32);
                    }
                }
                _ => {}
            }
        }

        // 3. Tick the transport (send acks, retransmit, etc.)
        transport.tick().await?;

        if transport.shutdown_in_progress() && transport.shutdown_acknowledged() {
            return Ok(());
        }
        if transport.shutdown_in_progress() && transport.shutdown_ack_timed_out() {
            return Ok(());
        }
        if transport.counterparty_shutdown_ack_sent() {
            return Ok(());
        }

        // 4. Render at a reasonable frame rate
        if last_render.elapsed() >= render_interval {
            // Create a display copy of the framebuffer for overlay application
            let mut overlay_fb = latest_remote_fb.clone();

            if let Some((pr, pc)) = predictor.apply_overlays(&mut overlay_fb) {
                overlay_fb.cursor_row = pr;
                overlay_fb.cursor_col = pc;
            }

            notification.apply(&mut overlay_fb);

            render.render(&overlay_fb)?;

            last_render = std::time::Instant::now();
        }

        // Wait for socket readability or a short timer (like mosh's select() on
        // stdin + network with a timeout). This avoids busy-looping while still
        // waking up promptly when the server sends data.
        tokio::select! {
            _ = transport.readable() => {},
            _ = tokio::time::sleep(Duration::from_millis(3)) => {},
        }
    }
}

/// Convert a crossterm key event to a Mosh action.
fn handle_key_event(event: &KeyEvent) -> Option<Vec<u8>> {
    // Match mosh's stdin behavior: act on keydown/autorepeat bytes only.
    if !matches!(event.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return None;
    }

    let code = event.code;
    let modifiers = event.modifiers;

    if modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = code {
            if c.is_ascii() {
                if let Some(ctrl) = encode_ctrl_char(c as u8) {
                    let mut out = vec![ctrl];
                    if modifiers.contains(KeyModifiers::ALT) {
                        out.insert(0, 0x1B);
                    }
                    return Some(out);
                }
            }
        }
    }

    let mut out = match code {
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            s.as_bytes().to_vec()
        }
        KeyCode::Enter => vec![0x0D],
        KeyCode::Backspace => vec![0x7F],
        KeyCode::Tab => vec![0x09],
        KeyCode::BackTab => b"\x1B[Z".to_vec(),
        KeyCode::Esc => vec![0x1B],
        KeyCode::Up => b"\x1BOA".to_vec(),
        KeyCode::Down => b"\x1BOB".to_vec(),
        KeyCode::Right => b"\x1BOC".to_vec(),
        KeyCode::Left => b"\x1BOD".to_vec(),
        KeyCode::Home => b"\x1BOH".to_vec(),
        KeyCode::End => b"\x1BOF".to_vec(),
        KeyCode::PageUp => b"\x1B[5~".to_vec(),
        KeyCode::PageDown => b"\x1B[6~".to_vec(),
        KeyCode::Insert => b"\x1B[2~".to_vec(),
        KeyCode::Delete => b"\x1B[3~".to_vec(),
        KeyCode::F(n) => {
            match n {
                1 => b"\x1BOP".to_vec(),
                2 => b"\x1BOQ".to_vec(),
                3 => b"\x1BOR".to_vec(),
                4 => b"\x1BOS".to_vec(),
                5 => b"\x1B[15~".to_vec(),
                6 => b"\x1B[17~".to_vec(),
                7 => b"\x1B[18~".to_vec(),
                8 => b"\x1B[19~".to_vec(),
                9 => b"\x1B[20~".to_vec(),
                10 => b"\x1B[21~".to_vec(),
                11 => b"\x1B[23~".to_vec(),
                12 => b"\x1B[24~".to_vec(),
                _ => return None,
            }
        }
        _ => return None,
    };

    if modifiers.contains(KeyModifiers::ALT) && !matches!(code, KeyCode::Esc) {
        out.insert(0, 0x1B);
    }

    Some(out)
}

fn is_command_key(event: &KeyEvent) -> bool {
    if !event.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }

    matches!(
        event.code,
        KeyCode::Char('6') | KeyCode::Char('^')
    )
}

/// Map Ctrl+ASCII combinations to terminal control bytes.
fn encode_ctrl_char(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a' + 1),
        b'A'..=b'Z' => Some(c - b'A' + 1),
        b' ' | b'2' | b'@' => Some(0x00),
        b'3' | b'[' => Some(0x1B),
        b'4' | b'\\' => Some(0x1C),
        b'5' | b']' => Some(0x1D),
        b'6' | b'^' => Some(0x1E),
        b'7' | b'_' => Some(0x1F),
        b'8' | b'?' => Some(0x7F),
        _ => None,
    }
}

/// Guard that ensures terminal cleanup on drop (normal exit or panic).
struct CleanupGuard;

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = renderer::Renderer::cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn test_ignores_key_release_events() {
        let release = key(KeyCode::Char('a'), KeyModifiers::NONE, KeyEventKind::Release);
        assert!(handle_key_event(&release).is_none());
    }

    #[test]
    fn test_accepts_press_and_repeat() {
        let press = key(KeyCode::Char('a'), KeyModifiers::NONE, KeyEventKind::Press);
        let repeat = key(KeyCode::Char('a'), KeyModifiers::NONE, KeyEventKind::Repeat);
        assert!(matches!(handle_key_event(&press), Some(v) if v == b"a"));
        assert!(matches!(handle_key_event(&repeat), Some(v) if v == b"a"));
    }

    #[test]
    fn test_alt_prefixes_escape() {
        let alt_x = key(KeyCode::Char('x'), KeyModifiers::ALT, KeyEventKind::Press);
        assert!(matches!(handle_key_event(&alt_x), Some(v) if v == b"\x1Bx"));
    }

    #[test]
    fn test_ctrl_c_is_sent_to_remote() {
        let ctrl_c = key(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert!(matches!(handle_key_event(&ctrl_c), Some(v) if v == vec![0x03]));
    }

    #[test]
    fn test_ctrl_digit_mappings_match_terminal_conventions() {
        let ctrl_2 = key(
            KeyCode::Char('2'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let ctrl_3 = key(
            KeyCode::Char('3'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert!(matches!(handle_key_event(&ctrl_2), Some(v) if v == vec![0x00]));
        assert!(matches!(handle_key_event(&ctrl_3), Some(v) if v == vec![0x1B]));
    }

    #[test]
    fn test_command_key_detection() {
        let cmd = key(
            KeyCode::Char('6'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let normal = key(KeyCode::Char('6'), KeyModifiers::NONE, KeyEventKind::Press);
        assert!(is_command_key(&cmd));
        assert!(!is_command_key(&normal));
    }

}
