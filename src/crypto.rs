//! Mosh cryptographic layer: AES-128-OCB encryption matching the Mosh wire format.
//!
//! Wire format of an encrypted datagram:
//!   [8-byte nonce suffix][ciphertext][16-byte OCB auth tag]
//!
//! The full 12-byte OCB nonce is: [4 zero bytes][8-byte nonce suffix]
//! The 8-byte nonce suffix encodes: (direction_bit << 63) | sequence_number

use aead::{Aead, KeyInit};
use aes::Aes128;
use anyhow::{bail, Context, Result};
use ocb3::Ocb3;

/// Nonce length for OCB3 (12 bytes).
const NONCE_LEN: usize = 12;

/// The 8-byte portion of the nonce that appears on the wire.
const NONCE_WIRE_LEN: usize = 8;

/// OCB authentication tag length (16 bytes).
const TAG_LEN: usize = 16;

/// Minimum encrypted datagram size: 8-byte nonce + 16-byte tag.
const MIN_DATAGRAM_LEN: usize = NONCE_WIRE_LEN + TAG_LEN;

/// Direction of communication (encoded in the high bit of the nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → Server: high bit = 0
    ToServer,
    /// Server → Client: high bit = 1
    ToClient,
}

impl Direction {
    fn bit(self) -> u64 {
        match self {
            Direction::ToServer => 0,
            Direction::ToClient => 1,
        }
    }
}

/// A 16-byte AES key parsed from Mosh's 22-character base64 format.
#[derive(Clone)]
pub struct Base64Key {
    key: [u8; 16],
}

impl Base64Key {
    /// Parse a Mosh base64 key string (22 characters, no padding).
    pub fn from_str(s: &str) -> Result<Self> {
        if s.len() != 22 {
            bail!("Mosh key must be exactly 22 base64 characters, got {}", s.len());
        }
        // Mosh keys are 22 chars of base64 with implicit "==" padding
        let padded = format!("{}==", s);
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &padded,
        )
        .context("Failed to decode base64 key")?;

        if decoded.len() != 16 {
            bail!("Decoded key must be 16 bytes, got {}", decoded.len());
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&decoded);
        Ok(Self { key })
    }

    /// Get the raw 16-byte key.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.key
    }
}

/// Build the full 12-byte OCB nonce from direction and sequence number.
pub fn make_nonce(direction: Direction, seq: u64) -> [u8; NONCE_LEN] {
    let val = (direction.bit() << 63) | (seq & 0x7FFF_FFFF_FFFF_FFFF);
    let mut nonce = [0u8; NONCE_LEN];
    // First 4 bytes are zero padding
    // Last 8 bytes are the big-endian value
    nonce[4..12].copy_from_slice(&val.to_be_bytes());
    nonce
}

/// Extract the 8-byte wire nonce from a full 12-byte nonce.
fn nonce_to_wire(nonce: &[u8; NONCE_LEN]) -> [u8; NONCE_WIRE_LEN] {
    let mut wire = [0u8; NONCE_WIRE_LEN];
    wire.copy_from_slice(&nonce[4..12]);
    wire
}

/// Expand an 8-byte wire nonce back to a full 12-byte OCB nonce.
fn wire_to_nonce(wire: &[u8; NONCE_WIRE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..12].copy_from_slice(wire);
    nonce
}

/// Parse the sequence number and direction from an 8-byte wire nonce.
pub fn parse_nonce(wire_nonce: &[u8; NONCE_WIRE_LEN]) -> (Direction, u64) {
    let val = u64::from_be_bytes(*wire_nonce);
    let direction = if val >> 63 == 1 {
        Direction::ToClient
    } else {
        Direction::ToServer
    };
    let seq = val & 0x7FFF_FFFF_FFFF_FFFF;
    (direction, seq)
}

/// A cryptographic session for encrypting/decrypting Mosh datagrams.
pub struct Session {
    cipher: Ocb3<Aes128, aead::consts::U12>,
}

impl Session {
    /// Create a new session from a Mosh base64 key.
    pub fn new(key: &Base64Key) -> Result<Self> {
        let aes_key = aes::cipher::generic_array::GenericArray::from_slice(key.as_bytes());
        let cipher = Ocb3::new(aes_key);
        Ok(Self { cipher })
    }

    /// Encrypt a plaintext message with the given nonce.
    ///
    /// Returns the wire format: [8-byte nonce][ciphertext + 16-byte tag]
    pub fn encrypt(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
        let aead_nonce = aead::generic_array::GenericArray::from_slice(nonce);
        let ciphertext = self
            .cipher
            .encrypt(aead_nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let wire_nonce = nonce_to_wire(nonce);
        let mut datagram = Vec::with_capacity(NONCE_WIRE_LEN + ciphertext.len());
        datagram.extend_from_slice(&wire_nonce);
        datagram.extend_from_slice(&ciphertext);
        Ok(datagram)
    }

    /// Decrypt a wire-format datagram.
    ///
    /// Input: [8-byte nonce][ciphertext + 16-byte tag]
    /// Returns: (full 12-byte nonce, plaintext)
    pub fn decrypt(&self, datagram: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        if datagram.len() < MIN_DATAGRAM_LEN {
            bail!(
                "Datagram too short: {} bytes (minimum {})",
                datagram.len(),
                MIN_DATAGRAM_LEN
            );
        }

        let mut wire_nonce = [0u8; NONCE_WIRE_LEN];
        wire_nonce.copy_from_slice(&datagram[..NONCE_WIRE_LEN]);
        let nonce = wire_to_nonce(&wire_nonce);

        let aead_nonce = aead::generic_array::GenericArray::from_slice(&nonce);
        let ciphertext = &datagram[NONCE_WIRE_LEN..];

        let plaintext = self
            .cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed: integrity check error"))?;

        Ok((nonce, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_roundtrip() {
        let nonce = make_nonce(Direction::ToClient, 42);
        let wire = nonce_to_wire(&nonce);
        let (dir, seq) = parse_nonce(&wire);
        assert_eq!(dir, Direction::ToClient);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_nonce_direction_encoding() {
        let nonce_server = make_nonce(Direction::ToServer, 1);
        let wire_server = nonce_to_wire(&nonce_server);
        let (dir, seq) = parse_nonce(&wire_server);
        assert_eq!(dir, Direction::ToServer);
        assert_eq!(seq, 1);

        let nonce_client = make_nonce(Direction::ToClient, 1);
        let wire_client = nonce_to_wire(&nonce_client);
        let (dir, seq) = parse_nonce(&wire_client);
        assert_eq!(dir, Direction::ToClient);
        assert_eq!(seq, 1);

        // They should differ in the high bit
        assert_ne!(wire_server, wire_client);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create a test key (16 bytes of zeros, base64-encoded is "AAAAAAAAAAAAAAAAAAAAAA")
        let key = Base64Key { key: [0u8; 16] };
        let session = Session::new(&key).unwrap();

        let plaintext = b"Hello, Mosh!";
        let nonce = make_nonce(Direction::ToServer, 1);

        let encrypted = session.encrypt(&nonce, plaintext).unwrap();
        let (dec_nonce, decrypted) = session.decrypt(&encrypted).unwrap();

        assert_eq!(nonce, dec_nonce);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_base64_key_parse() {
        // "AAAAAAAAAAAAAAAAAAAAAA" is 16 zero bytes in base64
        let key = Base64Key::from_str("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn test_tampered_datagram_fails() {
        let key = Base64Key { key: [0u8; 16] };
        let session = Session::new(&key).unwrap();

        let nonce = make_nonce(Direction::ToServer, 1);
        let mut encrypted = session.encrypt(&nonce, b"test").unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }

        assert!(session.decrypt(&encrypted).is_err());
    }
}
