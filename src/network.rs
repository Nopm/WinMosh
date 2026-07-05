//! Mosh network layer: UDP packet framing, timestamps, fragment encoding/decoding.
//!
//! Wire format after decryption:
//!   [2-byte timestamp BE][2-byte timestamp_reply BE][fragment_data...]
//!
//! Fragment format:
//!   [8-byte instruction_id BE][2-byte (final<<15 | frag_num) BE][payload...]

use anyhow::{bail, Result};
/// Network transport overhead: timestamps (4 bytes).
const TIMESTAMP_LEN: usize = 4;

/// Fragment header length: 8 (instruction_id) + 2 (fragment_num + final flag).
const FRAG_HEADER_LEN: usize = 10;

// ── MTU accounting (1:1 with mosh network.h) ────────────────────────────────

/// IPv4 MTU. Don't use full Ethernet-derived MTU; mobile networks have high
/// tunneling overhead (upstream uses a 1280-byte IPv4 MTU).
const DEFAULT_IPV4_MTU: usize = 1280;
/// IPv6 MTU. Use the guaranteed minimum to avoid fragmentation.
const DEFAULT_IPV6_MTU: usize = 1280;

/// For IPv4, guess the typical (minimum) header length.
const IPV4_HEADER_LEN: usize = 20 /* base IP header */ + 8 /* UDP */;
/// For IPv6, make a conservative guess about header size.
const IPV6_HEADER_LEN: usize = 40 /* base IPv6 header */
    + 16 /* 2 minimum-sized extension headers */
    + 8 /* UDP */;

/// Network transport overhead per packet (mosh `Connection::ADDED_BYTES`):
/// 8-byte seqno/nonce + 4 bytes of timestamps.
const ADDED_BYTES: usize = 8 + TIMESTAMP_LEN;

/// Crypto overhead per packet (mosh `Crypto::Session::ADDED_BYTES`): final OCB block.
const CRYPTO_ADDED_BYTES: usize = 16;

/// Application datagram MTU for the given address family
/// (mosh `Connection::set_MTU`).
pub fn mtu_for_family(is_ipv6: bool) -> usize {
    if is_ipv6 {
        DEFAULT_IPV6_MTU - IPV6_HEADER_LEN
    } else {
        DEFAULT_IPV4_MTU - IPV4_HEADER_LEN
    }
}

/// Maximum payload per fragment for the given address family:
/// app MTU - nonce/timestamps - OCB tag - fragment header.
/// (mosh: `connection->get_MTU() - Connection::ADDED_BYTES - Session::ADDED_BYTES`,
/// then `Fragmenter::make_fragments` subtracts `Fragment::frag_header_len`.)
pub fn max_frag_payload_for_family(is_ipv6: bool) -> usize {
    mtu_for_family(is_ipv6) - ADDED_BYTES - CRYPTO_ADDED_BYTES - FRAG_HEADER_LEN
}

/// A Mosh network packet (after decryption, before fragmentation parsing).
#[derive(Debug, Clone)]
pub struct Packet {
    /// 16-bit timestamp (milliseconds mod 65536).
    pub timestamp: u16,
    /// 16-bit echo of the last received timestamp.
    pub timestamp_reply: u16,
    /// Raw fragment data (may contain one or more fragments, though Mosh typically sends one).
    pub payload: Vec<u8>,
}

impl Packet {
    /// Serialize a packet into the cleartext wire format (before encryption).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TIMESTAMP_LEN + self.payload.len());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_reply.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse a packet from cleartext wire bytes (after decryption).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < TIMESTAMP_LEN {
            bail!(
                "Packet too short for timestamps: {} bytes",
                data.len()
            );
        }
        let timestamp = u16::from_be_bytes([data[0], data[1]]);
        let timestamp_reply = u16::from_be_bytes([data[2], data[3]]);
        let payload = data[TIMESTAMP_LEN..].to_vec();
        Ok(Self {
            timestamp,
            timestamp_reply,
            payload,
        })
    }
}

/// A single fragment of a transport instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Instruction ID this fragment belongs to.
    pub id: u64,
    /// Fragment number (0-based).
    pub fragment_num: u16,
    /// Whether this is the last fragment.
    pub is_final: bool,
    /// Fragment payload data.
    pub contents: Vec<u8>,
}

impl Fragment {
    /// Serialize a fragment to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAG_HEADER_LEN + self.contents.len());
        buf.extend_from_slice(&self.id.to_be_bytes());
        let combined: u16 = if self.is_final {
            (1u16 << 15) | self.fragment_num
        } else {
            self.fragment_num
        };
        buf.extend_from_slice(&combined.to_be_bytes());
        buf.extend_from_slice(&self.contents);
        buf
    }

    /// Parse a fragment from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FRAG_HEADER_LEN {
            bail!(
                "Fragment too short: {} bytes (need at least {})",
                data.len(),
                FRAG_HEADER_LEN
            );
        }
        let id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let combined = u16::from_be_bytes([data[8], data[9]]);
        let is_final = (combined >> 15) != 0;
        let fragment_num = combined & 0x7FFF;
        let contents = data[FRAG_HEADER_LEN..].to_vec();
        Ok(Self {
            id,
            fragment_num,
            is_final,
            contents,
        })
    }
}

/// Breaks an instruction (serialized protobuf) into MTU-sized fragments.
pub struct Fragmenter {
    next_instruction_id: u64,
    last_payload: Vec<u8>,
    last_max_frag_payload: usize,
    has_last: bool,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self {
            next_instruction_id: 0,
            last_payload: Vec::new(),
            last_max_frag_payload: usize::MAX,
            has_last: false,
        }
    }

    /// Fragment an instruction payload. Returns a list of fragments.
    pub fn make_fragments(&mut self, instruction: &[u8], max_frag_payload: usize) -> Vec<Fragment> {
        // Match upstream behavior: keep same instruction id when payload+MTU are identical.
        if !self.has_last
            || self.last_max_frag_payload != max_frag_payload
            || self.last_payload.as_slice() != instruction
        {
            self.next_instruction_id += 1;
        }
        self.has_last = true;
        self.last_max_frag_payload = max_frag_payload;
        self.last_payload.clear();
        self.last_payload.extend_from_slice(instruction);

        let id = self.next_instruction_id;

        if instruction.is_empty() {
            return vec![Fragment {
                id,
                fragment_num: 0,
                is_final: true,
                contents: Vec::new(),
            }];
        }

        let chunks: Vec<&[u8]> = instruction.chunks(max_frag_payload).collect();
        let total = chunks.len();
        // Mosh: fatal_assert( !( fragment_num & 0x8000 ) ) — effective limit on the
        // size of a terminal screen change or buffered user input.
        assert!(
            total <= 0x8000,
            "instruction too large to fragment: {} fragments",
            total
        );

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Fragment {
                id,
                fragment_num: i as u16,
                is_final: i == total - 1,
                contents: chunk.to_vec(),
            })
            .collect()
    }
}

/// Reassembles fragments into complete instructions.
pub struct FragmentAssembly {
    current_id: Option<u64>,
    fragments: Vec<Option<Fragment>>,
    fragments_arrived: usize,
    fragments_total: Option<usize>,
}

impl FragmentAssembly {
    pub fn new() -> Self {
        Self {
            current_id: None,
            fragments: Vec::new(),
            fragments_arrived: 0,
            fragments_total: None,
        }
    }

    /// Add a fragment. If this completes an instruction, returns the reassembled bytes.
    pub fn add_fragment(&mut self, fragment: Fragment) -> Option<Vec<u8>> {
        // Match upstream semantics: only one packet assembly in progress.
        if self.current_id != Some(fragment.id) {
            self.current_id = Some(fragment.id);
            self.fragments.clear();
            self.fragments.resize(fragment.fragment_num as usize + 1, None);
            self.fragments[fragment.fragment_num as usize] = Some(fragment.clone());
            self.fragments_arrived = 1;
            self.fragments_total = None;
        } else {
            let idx = fragment.fragment_num as usize;
            if self.fragments.len() <= idx {
                self.fragments.resize(idx + 1, None);
            }
            if let Some(existing) = &self.fragments[idx] {
                assert!(
                    existing == &fragment,
                    "FragmentAssembly duplicate fragment mismatch"
                );
            } else {
                self.fragments[idx] = Some(fragment.clone());
                self.fragments_arrived += 1;
            }
        }

        if fragment.is_final {
            let total = fragment.fragment_num as usize + 1;
            self.fragments_total = Some(total);
            if self.fragments.len() < total {
                self.fragments.resize(total, None);
            }
        }

        if let Some(total) = self.fragments_total {
            assert!(self.fragments_arrived <= total);
            if self.fragments_arrived == total {
                let mut out = Vec::new();
                for i in 0..total {
                    let frag = self.fragments[i]
                        .as_ref()
                        .expect("FragmentAssembly missing fragment despite complete count");
                    out.extend_from_slice(&frag.contents);
                }

                self.current_id = None;
                self.fragments.clear();
                self.fragments_arrived = 0;
                self.fragments_total = None;
                return Some(out);
            }
        }

        None
    }

}

/// Generate a 16-bit timestamp from a monotonic clock (milliseconds mod 65536).
///
/// 1:1 with mosh `Network::timestamp16()`: never returns 65535, which is
/// reserved as the "no timestamp" sentinel on the wire.
pub fn current_timestamp() -> u16 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    let ts = (start.elapsed().as_millis() % 65536) as u16;
    if ts == u16::MAX {
        ts.wrapping_add(1) // mosh: `if ( ts == uint16_t(-1) ) ts++;`
    } else {
        ts
    }
}

/// Difference between two 16-bit timestamps, handling wraparound.
/// 1:1 with mosh `Network::timestamp_diff()`.
pub fn timestamp_diff(tsnew: u16, tsold: u16) -> u16 {
    let mut diff = i32::from(tsnew) - i32::from(tsold);
    if diff < 0 {
        diff += 65536;
    }
    diff as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let pkt = Packet {
            timestamp: 12345,
            timestamp_reply: 54321,
            payload: b"hello world".to_vec(),
        };
        let bytes = pkt.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.timestamp, 12345);
        assert_eq!(parsed.timestamp_reply, 54321);
        assert_eq!(parsed.payload, b"hello world");
    }

    #[test]
    fn test_fragment_roundtrip() {
        let frag = Fragment {
            id: 42,
            fragment_num: 3,
            is_final: true,
            contents: b"test data".to_vec(),
        };
        let bytes = frag.to_bytes();
        let parsed = Fragment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.fragment_num, 3);
        assert!(parsed.is_final);
        assert_eq!(parsed.contents, b"test data");
    }

    #[test]
    fn test_fragment_not_final() {
        let frag = Fragment {
            id: 1,
            fragment_num: 5,
            is_final: false,
            contents: b"partial".to_vec(),
        };
        let bytes = frag.to_bytes();
        let parsed = Fragment::from_bytes(&bytes).unwrap();
        assert!(!parsed.is_final);
        assert_eq!(parsed.fragment_num, 5);
    }

    #[test]
    fn test_fragmenter_single_fragment() {
        let mut fragmenter = Fragmenter::new();
        let data = vec![0u8; 100];
        let frags = fragmenter.make_fragments(&data, max_frag_payload_for_family(false));
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_final);
        assert_eq!(frags[0].contents.len(), 100);
    }

    #[test]
    fn test_mtu_accounting_matches_upstream() {
        // mosh: IPv4 app MTU = 1280 - 28 = 1252; fragment payload = 1252 - 12 - 16 - 10.
        assert_eq!(mtu_for_family(false), 1252);
        assert_eq!(max_frag_payload_for_family(false), 1214);
        // mosh: IPv6 app MTU = 1280 - 64 = 1216; fragment payload = 1216 - 12 - 16 - 10.
        assert_eq!(mtu_for_family(true), 1216);
        assert_eq!(max_frag_payload_for_family(true), 1178);
    }

    #[test]
    fn test_timestamp_diff_wraparound() {
        assert_eq!(timestamp_diff(10, 5), 5);
        assert_eq!(timestamp_diff(5, 65530), 11);
        assert_eq!(timestamp_diff(0, 0), 0);
    }

    #[test]
    fn test_current_timestamp_never_returns_sentinel() {
        // Structural check: the sentinel branch maps 65535 -> 0 like upstream ts++.
        assert_eq!(u16::MAX.wrapping_add(1), 0);
        assert_ne!(current_timestamp(), u16::MAX);
    }

    #[test]
    fn test_fragmenter_multiple_fragments() {
        let mut fragmenter = Fragmenter::new();
        let data = vec![0u8; 250];
        let frags = fragmenter.make_fragments(&data, 100);
        assert_eq!(frags.len(), 3);
        assert!(!frags[0].is_final);
        assert!(!frags[1].is_final);
        assert!(frags[2].is_final);
        assert_eq!(frags[0].contents.len(), 100);
        assert_eq!(frags[1].contents.len(), 100);
        assert_eq!(frags[2].contents.len(), 50);
    }

    #[test]
    fn test_fragmenter_reuses_id_for_identical_payload() {
        let mut fragmenter = Fragmenter::new();
        let data = b"same payload";
        let a = fragmenter.make_fragments(data, 100);
        let b = fragmenter.make_fragments(data, 100);
        assert_eq!(a[0].id, b[0].id);
    }

    #[test]
    fn test_fragmenter_new_id_for_changed_payload() {
        let mut fragmenter = Fragmenter::new();
        let a = fragmenter.make_fragments(b"a", 100);
        let b = fragmenter.make_fragments(b"b", 100);
        assert_ne!(a[0].id, b[0].id);
    }

    #[test]
    fn test_fragment_assembly() {
        let mut fragmenter = Fragmenter::new();
        let data = b"Hello, World! This is a longer message for fragmentation testing.";
        let frags = fragmenter.make_fragments(data, 20);
        assert!(frags.len() > 1);

        let mut assembly = FragmentAssembly::new();
        let mut result = None;
        for frag in frags {
            result = assembly.add_fragment(frag);
        }
        assert_eq!(result.unwrap(), data.to_vec());
    }
}
