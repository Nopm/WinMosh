//! Mosh State Synchronization Protocol (SSP) transport layer.
//!
//! Manages bidirectional state synchronization over encrypted UDP:
//! - Tracks local state numbers and remote acknowledged state
//! - Computes diffs for outgoing state changes
//! - Processes incoming diffs and acknowledgments
//! - Handles retransmission timing

use crate::crypto::{self, Base64Key, Direction, Session};
use crate::network::{
    current_timestamp, Fragment, FragmentAssembly, Fragmenter, Packet, MAX_FRAG_PAYLOAD,
};
use crate::terminal::{Framebuffer, Terminal};
use crate::userstream::UserStream;
use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use prost::Message;
use rand::RngCore;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Protocol version number (matches upstream mosh).
const MOSH_PROTOCOL_VERSION: u32 = 2;

// ── Timing constants (1:1 with mosh transportsender.h) ─────────────────────
const SEND_INTERVAL_MIN: u64 = 20;           // ms between frames
const SEND_INTERVAL_MAX: u64 = 250;          // ms between frames
const ACK_INTERVAL: u64 = 3000;              // ms between empty acks
const ACK_DELAY: u64 = 100;                  // ms before delayed ack
const SHUTDOWN_RETRIES: u32 = 16;
const ACTIVE_RETRY_TIMEOUT: u64 = 10000;     // attempt to resend at frame rate
const SEND_MINDELAY: u64 = 8;                // ms to collect all input
const RECEIVED_QUEUE_LIMIT: usize = 1024;
const RECEIVER_QUENCH_MS: u64 = 15_000;
const CHAFF_MAX_LEN: usize = 16;

// ── RTT estimator constants ────────────────────────────────────────────────
const RTO_MIN_MS: u64 = 50;
const RTO_MAX_MS: u64 = 1000;
const SRTT_ALPHA: f64 = 0.125;
const RTTVAR_BETA: f64 = 0.25;

// ── Protobuf message types (defined inline, no protoc needed) ──────────────

/// Protobuf types matching the Mosh protocol.
pub mod proto {
    /// TransportInstruction messages (SSP framing).
    pub mod transportinstruction {
        /// A transport-layer instruction carrying state diffs and acks.
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Instruction {
            #[prost(uint32, optional, tag = "1")]
            pub protocol_version: ::core::option::Option<u32>,
            #[prost(uint64, optional, tag = "2")]
            pub old_num: ::core::option::Option<u64>,
            #[prost(uint64, optional, tag = "3")]
            pub new_num: ::core::option::Option<u64>,
            #[prost(uint64, optional, tag = "4")]
            pub ack_num: ::core::option::Option<u64>,
            #[prost(uint64, optional, tag = "5")]
            pub throwaway_num: ::core::option::Option<u64>,
            #[prost(bytes = "vec", optional, tag = "6")]
            pub diff: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
            #[prost(bytes = "vec", optional, tag = "7")]
            pub chaff: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        }
    }

    /// Client → Server user input messages.
    ///
    /// Tag numbers match upstream mosh `userinput.proto` exactly:
    ///   Keystroke.keys = 4, ResizeMessage.width = 5, height = 6
    ///   extend Instruction { keystroke = 2, resize = 3 }
    pub mod userinput {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Keystroke {
            #[prost(bytes = "vec", optional, tag = "4")]
            pub keys: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ResizeMessage {
            #[prost(int32, optional, tag = "5")]
            pub width: ::core::option::Option<i32>,
            #[prost(int32, optional, tag = "6")]
            pub height: ::core::option::Option<i32>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Instruction {
            #[prost(message, optional, tag = "2")]
            pub keystroke: ::core::option::Option<Keystroke>,
            #[prost(message, optional, tag = "3")]
            pub resize: ::core::option::Option<ResizeMessage>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct UserMessage {
            #[prost(message, repeated, tag = "1")]
            pub instruction: ::prost::alloc::vec::Vec<Instruction>,
        }
    }

    /// Server → Client host output messages.
    ///
    /// Tag numbers match upstream mosh `hostinput.proto` exactly:
    ///   HostBytes.hoststring = 4, ResizeMessage.width = 5, height = 6
    ///   EchoAck.echo_ack_num = 8
    ///   extend Instruction { hostbytes = 2, resize = 3, echoack = 7 }
    pub mod hostinput {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct HostBytes {
            #[prost(bytes = "vec", optional, tag = "4")]
            pub hoststring: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ResizeMessage {
            #[prost(int32, optional, tag = "5")]
            pub width: ::core::option::Option<i32>,
            #[prost(int32, optional, tag = "6")]
            pub height: ::core::option::Option<i32>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct EchoAck {
            #[prost(uint64, optional, tag = "8")]
            pub echo_ack_num: ::core::option::Option<u64>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Instruction {
            #[prost(message, optional, tag = "2")]
            pub hostbytes: ::core::option::Option<HostBytes>,
            #[prost(message, optional, tag = "3")]
            pub resize: ::core::option::Option<ResizeMessage>,
            #[prost(message, optional, tag = "7")]
            pub echoack: ::core::option::Option<EchoAck>,
        }

        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct HostMessage {
            #[prost(message, repeated, tag = "1")]
            pub instruction: ::prost::alloc::vec::Vec<Instruction>,
        }
    }
}

// ── Internal types ─────────────────────────────────────────────────────────

/// Timestamped state snapshot — 1:1 with mosh's `TimestampedState<MyState>`.
#[derive(Debug, Clone)]
struct TimestampedState {
    timestamp: Instant,
    num: u64,
    state: UserStream,
}

/// Remote terminal state modeled like upstream `statesync::Complete`.
#[derive(Debug, Clone)]
struct RemoteState {
    terminal: Terminal,
    echo_ack: u64,
}

impl RemoteState {
    fn new(width: usize, height: usize) -> Self {
        Self {
            terminal: Terminal::new(width, height),
            echo_ack: 0,
        }
    }

    fn apply_string(&mut self, diff: &[u8]) -> Result<()> {
        if diff.is_empty() {
            return Ok(());
        }

        let host_msg = proto::hostinput::HostMessage::decode(diff)
            .context("Failed to decode HostMessage")?;
        for inst in host_msg.instruction {
            if let Some(hb) = inst.hostbytes {
                if let Some(data) = hb.hoststring {
                    self.terminal.process(&data);
                }
            }
            if let Some(resize) = inst.resize {
                let w = resize.width.expect("HostMessage resize missing width");
                let h = resize.height.expect("HostMessage resize missing height");
                if w > 0 && h > 0 {
                    self.terminal.resize(w as usize, h as usize);
                }
            }
            if let Some(ea) = inst.echoack {
                if let Some(n) = ea.echo_ack_num {
                    assert!(n >= self.echo_ack, "HostMessage echoack regressed");
                    self.echo_ack = n;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TimestampedRemoteState {
    timestamp: Instant,
    num: u64,
    state: RemoteState,
}

/// RTT estimator (TCP-style SRTT/RTTVAR).
struct RttEstimator {
    srtt: f64,
    rttvar: f64,
    has_sample: bool,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            srtt: 100.0,
            rttvar: 50.0,
            has_sample: false,
        }
    }

    fn update(&mut self, rtt_ms: f64) {
        if !self.has_sample {
            self.srtt = rtt_ms;
            self.rttvar = rtt_ms / 2.0;
            self.has_sample = true;
        } else {
            self.rttvar =
                (1.0 - RTTVAR_BETA) * self.rttvar + RTTVAR_BETA * (self.srtt - rtt_ms).abs();
            self.srtt = (1.0 - SRTT_ALPHA) * self.srtt + SRTT_ALPHA * rtt_ms;
        }
    }

    /// Retransmission timeout in milliseconds.
    fn rto_ms(&self) -> u64 {
        let rto = (self.srtt + 4.0 * self.rttvar) as u64;
        rto.clamp(RTO_MIN_MS, RTO_MAX_MS)
    }
}

// ── Transport ──────────────────────────────────────────────────────────────

/// The Mosh transport: manages the SSP state exchange over encrypted UDP.
///
/// 1:1 port of mosh's TransportSender<UserStream> + network receive logic.
///
/// State model (matches mosh exactly):
/// - `current_state`: the full UserStream (all events pushed by the user)
/// - `sent_states`: list of (timestamp, num, state_snapshot) — front = acked, back = last sent
/// - `assumed_receiver_state`: index into sent_states — optimistic guess of receiver's state
/// - Diff is computed as `current_state.diff_from(assumed_state)` — never overlaps
pub struct Transport {
    // ── Network ──────────────────────────────────────────────────────
    session: Session,
    socket: UdpSocket,
    direction: Direction,
    next_seq: u64,
    fragmenter: Fragmenter,
    assembly: FragmentAssembly,
    rtt: RttEstimator,

    // ── TransportSender state (1:1 with mosh) ─────────────────────
    /// The current full user input state.
    current_state: UserStream,
    /// List of sent state snapshots.
    /// Front = known acked state. Back = last sent state.
    sent_states: Vec<TimestampedState>,
    /// Index into `sent_states` — optimistic guess of what receiver has.
    assumed_receiver_state: usize,
    /// For fragment creation.
    // (fragmenter above)
    /// Timing.
    next_ack_time: Instant,
    next_send_time: Option<Instant>, // None = infinity (don't send)
    /// Server's ack of our state (mosh: `ack_num` in TransportSender).
    ack_num: u64,
    pending_data_ack: bool,
    /// Time of first pending change to current state (mosh: mindelay_clock).
    mindelay_clock: Option<Instant>,
    /// Last time we heard from remote (mosh: last_heard).
    last_heard: Instant,
    shutdown_in_progress: bool,
    shutdown_tries: u32,
    shutdown_start: Option<Instant>,
    counterparty_shutdown_ack_sent: bool,

    // ── Receiver state (1:1 with mosh networktransport) ──────────
    /// Queue of received remote states, sorted by state number.
    received_states: Vec<TimestampedRemoteState>,
    /// If queue is overflowing, temporarily quench more insertions.
    receiver_quench_until: Option<Instant>,
    /// True when newest remote state advanced.
    remote_state_changed: bool,
    /// Last timestamp received (for timestamp_reply echo).
    last_recv_timestamp: u16,
    /// Last time we received any packet.
    last_recv_time: Instant,
    /// Remote session closure status (e.g., ICMP port unreachable after logout).
    remote_closed: Option<String>,
}

impl Transport {
    pub async fn new(
        key: &Base64Key,
        remote_addr: SocketAddr,
        direction: Direction,
        width: usize,
        height: usize,
    ) -> Result<Self> {
        let session = Session::new(key)?;
        let bind_addr = if remote_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr).await.context("Failed to bind UDP socket")?;
        socket.connect(remote_addr).await.context("Failed to connect UDP socket")?;

        let now = Instant::now();
        let initial_state = UserStream::new();
        let initial_ts = TimestampedState { timestamp: now, num: 0, state: initial_state.clone() };
        let initial_remote = TimestampedRemoteState {
            timestamp: now,
            num: 0,
            state: RemoteState::new(width, height),
        };

        Ok(Self {
            session, socket, direction,
            next_seq: 0,
            fragmenter: Fragmenter::new(),
            assembly: FragmentAssembly::new(),
            rtt: RttEstimator::new(),
            current_state: initial_state,
            sent_states: vec![initial_ts],
            assumed_receiver_state: 0,
            next_ack_time: now,
            next_send_time: None,
            ack_num: 0,
            pending_data_ack: false,
            mindelay_clock: None,
            last_heard: now,
            shutdown_in_progress: false,
            shutdown_tries: 0,
            shutdown_start: None,
            counterparty_shutdown_ack_sent: false,
            received_states: vec![initial_remote],
            receiver_quench_until: None,
            remote_state_changed: false,
            last_recv_timestamp: u16::MAX,
            last_recv_time: now,
            remote_closed: None,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().context("Failed to get local addr")
    }

    pub fn time_since_last_recv(&self) -> Duration { self.last_recv_time.elapsed() }

    /// In mosh, this checks if the remote address is known.
    /// We always know it (from SSH bootstrap + socket connect), so always true.
    pub fn has_remote_addr(&self) -> bool {
        true
    }

    /// Whether we've received at least one packet from the server.
    pub fn has_received_data(&self) -> bool {
        self.received_states.last().map(|s| s.num).unwrap_or(0) > 0
            || self.last_recv_timestamp != u16::MAX
    }

    pub fn remote_close_reason(&self) -> Option<&str> {
        self.remote_closed.as_deref()
    }

    pub fn start_shutdown(&mut self) {
        if !self.shutdown_in_progress {
            self.shutdown_in_progress = true;
            self.shutdown_start = Some(Instant::now());
        }
    }

    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress
    }

    pub fn shutdown_acknowledged(&self) -> bool {
        self.sent_states
            .first()
            .map(|s| s.num == u64::MAX)
            .unwrap_or(false)
    }

    pub fn shutdown_ack_timed_out(&self) -> bool {
        if !self.shutdown_in_progress {
            return false;
        }
        if self.shutdown_tries >= SHUTDOWN_RETRIES {
            return true;
        }
        self.shutdown_start
            .map(|t| t.elapsed() >= Duration::from_millis(ACTIVE_RETRY_TIMEOUT))
            .unwrap_or(false)
    }

    pub fn counterparty_shutdown_ack_sent(&self) -> bool {
        self.counterparty_shutdown_ack_sent
    }

    pub fn latest_remote_framebuffer(&self) -> &Framebuffer {
        &self
            .received_states
            .last()
            .expect("received_states always contains initial state")
            .state
            .terminal
            .fb
    }

    pub fn latest_remote_echo_ack(&self) -> u64 {
        self.received_states
            .last()
            .map(|s| s.state.echo_ack)
            .unwrap_or(0)
    }

    pub fn take_remote_state_changed(&mut self) -> bool {
        let changed = self.remote_state_changed;
        self.remote_state_changed = false;
        changed
    }

    /// Mosh: `get_current_state().push_back(UserByte(c))` for each byte.
    pub fn push_user_input(&mut self, keys: &[u8]) {
        assert!(
            !self.shutdown_in_progress,
            "push_user_input called during shutdown"
        );
        self.current_state.push_keystrokes(keys);
        if self.mindelay_clock.is_none() {
            self.mindelay_clock = Some(Instant::now());
        }
    }

    /// Mosh: `get_current_state().push_back(Resize(w,h))`.
    pub fn push_resize(&mut self, width: i32, height: i32) {
        assert!(
            !self.shutdown_in_progress,
            "push_resize called during shutdown"
        );
        self.current_state.push_resize(width, height);
        if self.mindelay_clock.is_none() {
            self.mindelay_clock = Some(Instant::now());
        }
    }

    // ── send_interval (1:1 with mosh) ──────────────────────────────
    fn send_interval(&self) -> u64 {
        ((self.rtt.srtt / 2.0).ceil() as u64).clamp(SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)
    }

    // ── update_assumed_receiver_state (1:1 with mosh) ──────────────
    fn update_assumed_receiver_state(&mut self) {
        let now = Instant::now();
        let timeout_window = Duration::from_millis(self.rtt.rto_ms() + ACK_DELAY);

        // Start from known acked state (front), advance optimistically
        self.assumed_receiver_state = 0;
        for i in 1..self.sent_states.len() {
            if now.duration_since(self.sent_states[i].timestamp) < timeout_window {
                self.assumed_receiver_state = i;
            } else {
                return;
            }
        }
    }

    // ── rationalize_states (1:1 with mosh) ─────────────────────────
    fn rationalize_states(&mut self) {
        let known = self.sent_states[0].state.clone();
        self.current_state.subtract(&known);
        for ts in &mut self.sent_states {
            ts.state.subtract(&known);
        }
    }

    // ── calculate_timers (1:1 with mosh) ───────────────────────────
    fn calculate_timers(&mut self) {
        let now = Instant::now();
        self.update_assumed_receiver_state();
        self.rationalize_states();

        if self.pending_data_ack && self.next_ack_time > now + Duration::from_millis(ACK_DELAY) {
            self.next_ack_time = now + Duration::from_millis(ACK_DELAY);
        }

        let send_iv = Duration::from_millis(self.send_interval());
        let back = &self.sent_states[self.sent_states.len() - 1];
        let assumed = &self.sent_states[self.assumed_receiver_state];

        if self.current_state != back.state {
            // New data to send
            if self.mindelay_clock.is_none() {
                self.mindelay_clock = Some(now);
            }
            let mindelay_at = self.mindelay_clock.unwrap() + Duration::from_millis(SEND_MINDELAY);
            let interval_at = back.timestamp + send_iv;
            self.next_send_time = Some(std::cmp::max(mindelay_at, interval_at));
        } else if self.current_state != assumed.state
            && self.last_heard + Duration::from_millis(ACTIVE_RETRY_TIMEOUT) > now
        {
            // Retransmit at send_interval rate
            let mut nst = back.timestamp + send_iv;
            if let Some(mc) = self.mindelay_clock {
                nst = std::cmp::max(nst, mc + Duration::from_millis(SEND_MINDELAY));
            }
            self.next_send_time = Some(nst);
        } else if self.current_state != self.sent_states[0].state
            && self.last_heard + Duration::from_millis(ACTIVE_RETRY_TIMEOUT) > now
        {
            // Timeout-based retransmit
            let rto = Duration::from_millis(self.rtt.rto_ms());
            self.next_send_time = Some(back.timestamp + rto + Duration::from_millis(ACK_DELAY));
        } else {
            self.next_send_time = None;
        }

        // Match upstream: speed up shutdown sequence and shutdown ACK replies.
        if self.shutdown_in_progress || self.ack_num == u64::MAX {
            self.next_ack_time = back.timestamp + send_iv;
        }
    }

    // ── attempt_prospective_resend_optimization (1:1 with mosh) ────
    fn attempt_prospective_resend_optimization(&mut self, proposed_diff: &mut Vec<u8>) {
        if self.assumed_receiver_state == 0 {
            return;
        }
        let resend_diff = self.current_state.diff_from(&self.sent_states[0].state);
        if resend_diff.len() <= proposed_diff.len()
            || (resend_diff.len() < 1000 && resend_diff.len() - proposed_diff.len() < 100)
        {
            self.assumed_receiver_state = 0;
            *proposed_diff = resend_diff;
        }
    }

    // ── add_sent_state (1:1 with mosh) ─────────────────────────────
    fn add_sent_state(&mut self, timestamp: Instant, num: u64, state: &UserStream) {
        self.sent_states.push(TimestampedState {
            timestamp, num, state: state.clone(),
        });
        if self.sent_states.len() > 32 {
            // Mosh: erase from middle of queue
            let mid = self.sent_states.len() - 16;
            self.sent_states.remove(mid);
            // Adjust assumed_receiver_state index
            if self.assumed_receiver_state >= mid {
                self.assumed_receiver_state -= 1;
            } else if self.assumed_receiver_state > self.sent_states.len() - 1 {
                self.assumed_receiver_state = self.sent_states.len() - 1;
            }
        }
    }

    // ── send_to_receiver (1:1 with mosh) ───────────────────────────
    async fn send_to_receiver(&mut self, diff: &[u8]) -> Result<()> {
        let back_num = self.sent_states.last().unwrap().num;
        let new_num = if self.shutdown_in_progress {
            let new_num = u64::MAX;
            if self.sent_states.last().map(|s| s.num) == Some(new_num) {
                self.sent_states.last_mut().unwrap().timestamp = Instant::now();
            } else {
                let state_clone = self.current_state.clone();
                self.add_sent_state(Instant::now(), new_num, &state_clone);
            }
            new_num
        } else if self.current_state == self.sent_states.last().unwrap().state {
            // Previously sent same state — reuse number, update timestamp
            self.sent_states.last_mut().unwrap().timestamp = Instant::now();
            back_num
        } else {
            let n = back_num + 1;
            let state_clone = self.current_state.clone();
            self.add_sent_state(Instant::now(), n, &state_clone);
            n
        };

        let assumed_num = self.sent_states[self.assumed_receiver_state].num;
        self.send_in_fragments(diff, new_num, assumed_num).await?;

        // Advance assumed_receiver_state to last sent
        self.assumed_receiver_state = self.sent_states.len() - 1;
        self.next_ack_time = Instant::now() + Duration::from_millis(ACK_INTERVAL);
        self.next_send_time = None;
        Ok(())
    }

    // ── send_empty_ack (1:1 with mosh) ─────────────────────────────
    async fn send_empty_ack(&mut self) -> Result<()> {
        // Match mosh transportsender: empty ACK advances state number.
        let mut new_num = self.sent_states.last().unwrap().num + 1;
        if self.shutdown_in_progress {
            new_num = u64::MAX;
        }
        let state_clone = self.current_state.clone();
        self.add_sent_state(Instant::now(), new_num, &state_clone);
        let assumed_num = self.sent_states[self.assumed_receiver_state].num;
        self.send_in_fragments(&[], new_num, assumed_num).await?;
        self.next_ack_time = Instant::now() + Duration::from_millis(ACK_INTERVAL);
        self.next_send_time = None;
        Ok(())
    }

    // ── send_in_fragments (1:1 with mosh) ──────────────────────────
    async fn send_in_fragments(&mut self, diff: &[u8], new_num: u64, old_num: u64) -> Result<()> {
        let instruction = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(old_num),
            new_num: Some(new_num),
            ack_num: Some(self.ack_num),
            throwaway_num: Some(self.sent_states[0].num),
            diff: Some(diff.to_vec()),
            chaff: Some(make_chaff()),
        };

        if new_num == u64::MAX {
            self.shutdown_tries = self.shutdown_tries.saturating_add(1);
        }
        if self.ack_num == u64::MAX {
            self.counterparty_shutdown_ack_sent = true;
        }

        let encoded = instruction.encode_to_vec();
        let compressed = zlib_compress(&encoded)?;
        let fragments = self.fragmenter.make_fragments(&compressed, MAX_FRAG_PAYLOAD);
        for frag in fragments {
            self.send_packet(&frag.to_bytes()).await?;
        }
        self.pending_data_ack = false;
        Ok(())
    }

    // ── tick (1:1 with mosh) ───────────────────────────────────────
    pub async fn tick(&mut self) -> Result<()> {
        if self.remote_closed.is_some() {
            return Ok(());
        }

        self.calculate_timers();

        if !self.has_remote_addr() {
            return Ok(());
        }

        let now = Instant::now();
        let ack_due = now >= self.next_ack_time;
        let send_due = self.next_send_time.map(|t| now >= t).unwrap_or(false);

        if !ack_due && !send_due {
            return Ok(());
        }

        let assumed = &self.sent_states[self.assumed_receiver_state];
        let mut diff = self.current_state.diff_from(&assumed.state);

        self.attempt_prospective_resend_optimization(&mut diff);

        if diff.is_empty() {
            if ack_due {
                self.send_empty_ack().await?;
                self.mindelay_clock = None;
            }
            if send_due {
                self.next_send_time = None;
                self.mindelay_clock = None;
            }
        } else if send_due || ack_due {
            self.send_to_receiver(&diff).await?;
            self.mindelay_clock = None;
        }

        Ok(())
    }

    // ── process_acknowledgment_through (1:1 with mosh) ─────────────
    fn process_acknowledgment_through(&mut self, ack_num: u64) {
        // Find entry with matching num
        let found = self.sent_states.iter().any(|s| s.num == ack_num);
        if !found {
            return; // Ack for culled state, ignore
        }
        // Erase all entries with num < ack_num
        let old_len = self.sent_states.len();
        self.sent_states.retain(|s| s.num >= ack_num);
        let removed = old_len - self.sent_states.len();
        // Adjust assumed_receiver_state index
        self.assumed_receiver_state = self.assumed_receiver_state.saturating_sub(removed);
    }

    // ── Packet send/recv ───────────────────────────────────────────

    async fn send_packet(&mut self, payload: &[u8]) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let nonce = crypto::make_nonce(self.direction, seq);
        let pkt = Packet {
            timestamp: current_timestamp(),
            timestamp_reply: self.last_recv_timestamp,
            payload: payload.to_vec(),
        };
        let encrypted = self.session.encrypt(&nonce, &pkt.to_bytes())?;
        if let Err(e) = self.socket.send(&encrypted).await {
            if is_remote_close_error(&e) {
                self.mark_remote_closed(e);
                return Ok(());
            }
            return Err(e.into());
        }
        Ok(())
    }

    pub async fn readable(&self) -> Result<()> {
        self.socket.readable().await.context("socket readable failed")?;
        Ok(())
    }

    /// Drain all currently readable UDP datagrams.
    pub fn drain_recv(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];

        loop {
            let n = match self.socket.try_recv(&mut buf) {
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if is_remote_close_error(&e) => {
                    self.mark_remote_closed(e);
                    break;
                }
                Err(e) => return Err(e.into()),
            };

            self.process_datagram(&buf[..n])?;
        }

        Ok(())
    }

    fn mark_remote_closed(&mut self, err: std::io::Error) {
        if self.remote_closed.is_none() {
            let graceful = self.shutdown_in_progress || self.ack_num == u64::MAX;
            if graceful {
                self.remote_closed = Some("server closed the session".to_string());
            } else {
                self.remote_closed = Some(format!(
                    "remote host closed session ({})",
                    err
                ));
            }
            log::info!("{}", self.remote_closed.as_ref().unwrap());
        }
    }

    fn process_throwaway_until(&mut self, throwaway_num: u64) -> Result<()> {
        self.received_states.retain(|s| s.num >= throwaway_num);
        if self.received_states.is_empty() {
            anyhow::bail!(
                "receiver state queue underflow after throwaway {}",
                throwaway_num
            );
        }
        Ok(())
    }

    fn process_datagram(&mut self, datagram: &[u8]) -> Result<()> {
        let (nonce, plaintext) = self.session.decrypt(datagram)?;
        let _ = crypto::parse_nonce(&{
            let mut w = [0u8; 8]; w.copy_from_slice(&nonce[4..12]); w
        });

        let packet = Packet::from_bytes(&plaintext)?;
        self.last_recv_time = Instant::now();
        self.last_recv_timestamp = packet.timestamp;
        self.last_heard = Instant::now();

        // RTT from timestamp echo
        if packet.timestamp_reply != u16::MAX {
            let now_ts = current_timestamp();
            let rtt_ms = if now_ts >= packet.timestamp_reply {
                (now_ts - packet.timestamp_reply) as f64
            } else {
                (65536 + now_ts as u32 - packet.timestamp_reply as u32) as f64
            };
            if rtt_ms < 10000.0 { self.rtt.update(rtt_ms); }
        }

        if packet.payload.is_empty() {
            return Ok(());
        }

        let fragment = Fragment::from_bytes(&packet.payload)?;
        let assembled = self.assembly.add_fragment(fragment);

        if let Some(compressed) = assembled {
            let bytes = zlib_decompress(&compressed).context("zlib decompress failed")?;
            let ti = proto::transportinstruction::Instruction::decode(bytes.as_slice())
                .context("Failed to decode TransportInstruction")?;

            let ver = ti.protocol_version.unwrap_or_default();
            if ver != MOSH_PROTOCOL_VERSION {
                anyhow::bail!(
                    "mosh protocol version mismatch: peer={} local={}",
                    ver,
                    MOSH_PROTOCOL_VERSION
                );
            }

            // Process ack (mosh: process_acknowledgment_through + set_ack_num)
            let ack = ti.ack_num.unwrap_or_default();
            self.process_acknowledgment_through(ack);

            let new_num = ti.new_num.unwrap_or_default();

            // Ignore duplicate state numbers.
            if self.received_states.iter().any(|s| s.num == new_num) {
                return Ok(());
            }

            // Accept only if referenced base exists in our queue.
            let old_num = ti.old_num.unwrap_or_default();
            let Some(reference_idx) = self.received_states.iter().position(|s| s.num == old_num) else {
                log::debug!(
                    "drop remote state {}: reference {} not in queue",
                    new_num,
                    old_num
                );
                return Ok(());
            };

            let reference_state = self.received_states[reference_idx].clone();
            self.process_throwaway_until(ti.throwaway_num.unwrap_or_default())?;

            // Upstream keeps a hard cap on receiver queue growth.
            if self.received_states.len() > RECEIVED_QUEUE_LIMIT {
                let now = Instant::now();
                if self
                    .receiver_quench_until
                    .map(|until| now < until)
                    .unwrap_or(false)
                {
                    log::debug!("receiver queue quenching state {}", new_num);
                    return Ok(());
                }
                self.receiver_quench_until =
                    Some(now + Duration::from_millis(RECEIVER_QUENCH_MS));
            }

            let mut new_state = reference_state;
            new_state.timestamp = Instant::now();
            new_state.num = new_num;

            let diff = ti.diff.unwrap_or_default();
            let had_diff = !diff.is_empty();
            if had_diff {
                new_state.state.apply_string(&diff)?;
            }

            let prev_latest = self.received_states.last().map(|s| s.num).unwrap_or(0);
            let insert_idx = self
                .received_states
                .iter()
                .position(|s| s.num > new_state.num)
                .unwrap_or(self.received_states.len());
            let out_of_order = insert_idx < self.received_states.len();
            self.received_states.insert(insert_idx, new_state);

            if out_of_order {
                log::debug!(
                    "accept out-of-order remote state {} from {} [ack {}]",
                    new_num,
                    old_num,
                    ack
                );
                return Ok(());
            } else {
                log::debug!(
                    "accept remote state {} from {} [ack {}]",
                    new_num,
                    old_num,
                    ack
                );
            }

            let latest_num = self.received_states.last().map(|s| s.num).unwrap_or(0);
            self.ack_num = latest_num;
            if had_diff {
                self.pending_data_ack = true;
            }
            if latest_num > prev_latest {
                self.remote_state_changed = true;
            }
        }
        Ok(())
    }

    pub fn acked_state_num(&self) -> u64 {
        self.sent_states[0].num
    }

    pub fn sent_state_last_num(&self) -> u64 {
        self.sent_states
            .last()
            .map(|s| s.num)
            .unwrap_or(0)
    }

    pub fn send_interval_ms(&self) -> u64 {
        self.send_interval()
    }
}

// ── Zlib compression (Mosh compresses protobuf before encryption) ───────────

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .context("zlib compression write failed")?;
    encoder.finish().context("zlib compression finish failed")
}

fn make_chaff() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = (rng.next_u32() as usize) % (CHAFF_MAX_LEN + 1);
    let mut out = vec![0u8; len];
    if len > 0 {
        rng.fill_bytes(&mut out);
    }
    out
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .context("zlib decompression failed")?;
    Ok(decompressed)
}

fn is_remote_close_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{make_nonce, Direction, Session};

    async fn test_transport() -> (Transport, UdpSocket, Base64Key) {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let key = Base64Key::from_str("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let transport = Transport::new(&key, peer_addr, Direction::ToServer, 80, 24)
            .await
            .unwrap();
        (transport, peer, key)
    }

    fn build_server_datagram(
        key: &Base64Key,
        seq: u64,
        instruction: proto::transportinstruction::Instruction,
    ) -> Vec<u8> {
        let encoded = instruction.encode_to_vec();
        let compressed = zlib_compress(&encoded).unwrap();
        let fragment = Fragment {
            id: 1,
            fragment_num: 0,
            is_final: true,
            contents: compressed,
        };
        let packet = Packet {
            timestamp: 1234,
            timestamp_reply: u16::MAX,
            payload: fragment.to_bytes(),
        };
        let session = Session::new(key).unwrap();
        let nonce = make_nonce(Direction::ToClient, seq);
        session.encrypt(&nonce, &packet.to_bytes()).unwrap()
    }

    fn host_diff(bytes: &[u8]) -> Vec<u8> {
        let msg = proto::hostinput::HostMessage {
            instruction: vec![proto::hostinput::Instruction {
                hostbytes: Some(proto::hostinput::HostBytes {
                    hoststring: Some(bytes.to_vec()),
                }),
                resize: None,
                echoack: None,
            }],
        };
        msg.encode_to_vec()
    }

    #[tokio::test]
    async fn empty_ack_creates_new_state_number() {
        let (mut transport, _peer, _key) = test_transport().await;
        assert_eq!(transport.sent_states.len(), 1);

        transport.next_ack_time = Instant::now() - Duration::from_millis(1);
        transport.tick().await.unwrap();

        assert_eq!(transport.sent_states.len(), 2);
        assert_eq!(transport.sent_states.last().unwrap().num, 1);
    }

    #[tokio::test]
    async fn latest_received_state_updates_ack_num() {
        let (mut transport, _peer, key) = test_transport().await;
        let ti = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(1),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(Vec::new()),
            chaff: None,
        };
        let datagram = build_server_datagram(&key, 0, ti);
        transport.process_datagram(&datagram).unwrap();

        assert_eq!(transport.ack_num, 1);
    }

    #[tokio::test]
    async fn accepts_state_from_older_base_when_reference_exists() {
        let (mut transport, _peer, key) = test_transport().await;

        let first = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(1),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"a")),
            chaff: None,
        };
        let first_dgram = build_server_datagram(&key, 0, first);
        transport.process_datagram(&first_dgram).unwrap();

        let from_older_base = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(2),
            ack_num: Some(1),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"ab")),
            chaff: None,
        };
        let second_dgram = build_server_datagram(&key, 1, from_older_base);
        transport.process_datagram(&second_dgram).unwrap();

        assert_eq!(transport.ack_num, 2);
        let fb = transport.latest_remote_framebuffer();
        assert_eq!(fb.cells[0][0].character, 'a');
        assert_eq!(fb.cells[0][1].character, 'b');
    }

    #[tokio::test]
    async fn drops_state_when_reference_missing() {
        let (mut transport, _peer, key) = test_transport().await;

        // Advance to state 1.
        let first = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(1),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"a")),
            chaff: None,
        };
        let first_dgram = build_server_datagram(&key, 0, first);
        transport.process_datagram(&first_dgram).unwrap();

        // Advance to state 2 and discard state 0 via throwaway=1.
        let second = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(1),
            new_num: Some(2),
            ack_num: Some(1),
            throwaway_num: Some(1),
            diff: Some(host_diff(b"ab")),
            chaff: None,
        };
        let second_dgram = build_server_datagram(&key, 1, second);
        transport.process_datagram(&second_dgram).unwrap();

        // Now reference to discarded state 0 should be ignored.
        let missing_ref = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(3),
            ack_num: Some(2),
            throwaway_num: Some(1),
            diff: Some(host_diff(b"abc")),
            chaff: None,
        };
        let third_dgram = build_server_datagram(&key, 2, missing_ref);
        transport.process_datagram(&third_dgram).unwrap();

        assert_eq!(transport.ack_num, 2);
    }

    #[tokio::test]
    async fn inserts_out_of_order_states_without_rewinding_latest() {
        let (mut transport, _peer, key) = test_transport().await;

        let newer = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(2),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"ab")),
            chaff: None,
        };
        let newer_dgram = build_server_datagram(&key, 0, newer);
        transport.process_datagram(&newer_dgram).unwrap();
        assert_eq!(transport.ack_num, 2);

        let older = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(1),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"a")),
            chaff: None,
        };
        let older_dgram = build_server_datagram(&key, 1, older);
        transport.process_datagram(&older_dgram).unwrap();

        assert_eq!(transport.ack_num, 2);
        assert_eq!(transport.received_states.len(), 3);
        assert_eq!(transport.received_states[0].num, 0);
        assert_eq!(transport.received_states[1].num, 1);
        assert_eq!(transport.received_states[2].num, 2);
    }

    #[tokio::test]
    async fn start_shutdown_sends_terminal_state_number_max() {
        let (mut transport, _peer, _key) = test_transport().await;
        transport.start_shutdown();
        let send_iv = transport.send_interval_ms();
        transport.sent_states.last_mut().unwrap().timestamp =
            Instant::now() - Duration::from_millis(send_iv + 1);
        transport.tick().await.unwrap();

        assert!(transport.shutdown_in_progress());
        assert_eq!(transport.sent_states.last().unwrap().num, u64::MAX);
    }

    #[tokio::test]
    async fn shutdown_timeout_after_retry_budget() {
        let (mut transport, _peer, _key) = test_transport().await;
        transport.start_shutdown();
        transport.shutdown_tries = SHUTDOWN_RETRIES;
        assert!(transport.shutdown_ack_timed_out());
    }

    #[tokio::test]
    async fn remote_shutdown_sets_ack_and_sends_counterparty_ack() {
        let (mut transport, _peer, key) = test_transport().await;

        let first = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(0),
            new_num: Some(1),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(host_diff(b"a")),
            chaff: None,
        };
        let first_dgram = build_server_datagram(&key, 0, first);
        transport.process_datagram(&first_dgram).unwrap();

        let shutdown = proto::transportinstruction::Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(1),
            new_num: Some(u64::MAX),
            ack_num: Some(0),
            throwaway_num: Some(0),
            diff: Some(Vec::new()),
            chaff: None,
        };
        let shutdown_dgram = build_server_datagram(&key, 1, shutdown);
        transport.process_datagram(&shutdown_dgram).unwrap();
        assert_eq!(transport.ack_num, u64::MAX);
        assert!(!transport.counterparty_shutdown_ack_sent());

        let send_iv = transport.send_interval_ms();
        transport.sent_states.last_mut().unwrap().timestamp =
            Instant::now() - Duration::from_millis(send_iv + 1);
        transport.tick().await.unwrap();
        assert!(transport.counterparty_shutdown_ack_sent());
    }

    #[test]
    fn connection_reset_is_treated_as_remote_close() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(is_remote_close_error(&err));
    }
}
