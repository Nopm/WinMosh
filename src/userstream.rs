//! UserStream: 1:1 port of mosh's `UserStream` from `statesync/user.{h,cc}`.
//!
//! A monotonically-growing deque of user events (keystrokes + resizes).
//! Supports diff_from(), apply_string(), and subtract() for SSP state sync.

use crate::transport::proto::userinput;
use prost::Message;

/// A single user event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserEvent {
    Keystroke(u8),
    Resize { width: i32, height: i32 },
}

/// The client-side user input state — a deque of events.
/// Mirrors mosh's `UserStream` class exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStream {
    actions: Vec<UserEvent>,
}

#[allow(dead_code)]
impl UserStream {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    /// Push a single keystroke byte (mosh: push_back(UserByte)).
    pub fn push_keystroke(&mut self, byte: u8) {
        self.actions.push(UserEvent::Keystroke(byte));
    }

    /// Push keystroke bytes.
    pub fn push_keystrokes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.actions.push(UserEvent::Keystroke(b));
        }
    }

    /// Push a resize event (mosh: push_back(Resize)).
    pub fn push_resize(&mut self, width: i32, height: i32) {
        self.actions.push(UserEvent::Resize { width, height });
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Remove a prefix of events that match `prefix`.
    /// Mosh: `UserStream::subtract(const UserStream *prefix)`.
    pub fn subtract(&mut self, prefix: &UserStream) {
        if self == prefix {
            self.actions.clear();
            return;
        }
        let prefix_len = prefix.actions.len();
        assert!(
            self.actions.len() >= prefix_len,
            "UserStream::subtract prefix longer than state (state_len={}, prefix_len={})",
            self.actions.len(),
            prefix_len
        );
        assert!(
            self.actions[..prefix_len] == prefix.actions[..],
            "UserStream::subtract prefix mismatch"
        );
        self.actions.drain(..prefix_len);
    }

    /// Compute the diff from `existing` to `self` as a serialized UserMessage.
    /// Mosh: `UserStream::diff_from(const UserStream &existing)`.
    ///
    /// Skips over the common prefix (existing's events), then serializes
    /// the remaining events. Consecutive keystrokes are batched into a
    /// single Keystroke instruction (matching mosh's batching behavior).
    pub fn diff_from(&self, existing: &UserStream) -> Vec<u8> {
        let start = existing.actions.len();
        assert!(
            start <= self.actions.len(),
            "UserStream::diff_from existing longer than state (state_len={}, existing_len={})",
            self.actions.len(),
            start
        );
        assert!(
            self.actions[..start] == existing.actions[..],
            "UserStream::diff_from existing is not prefix"
        );
        if start >= self.actions.len() {
            return Vec::new(); // no new events
        }

        let mut output = userinput::UserMessage {
            instruction: Vec::new(),
        };

        for event in &self.actions[start..] {
            match event {
                UserEvent::Keystroke(byte) => {
                    // Batch consecutive keystrokes into one Instruction
                    // (mosh: appends to last keystroke instruction if it exists)
                    let can_batch = output
                        .instruction
                        .last()
                        .map(|inst| inst.keystroke.is_some() && inst.resize.is_none())
                        .unwrap_or(false);

                    if can_batch {
                        let last = output.instruction.last_mut().unwrap();
                        last.keystroke
                            .as_mut()
                            .unwrap()
                            .keys
                            .as_mut()
                            .unwrap()
                            .push(*byte);
                    } else {
                        output.instruction.push(userinput::Instruction {
                            keystroke: Some(userinput::Keystroke {
                                keys: Some(vec![*byte]),
                            }),
                            resize: None,
                        });
                    }
                }
                UserEvent::Resize { width, height } => {
                    output.instruction.push(userinput::Instruction {
                        keystroke: None,
                        resize: Some(userinput::ResizeMessage {
                            width: Some(*width),
                            height: Some(*height),
                        }),
                    });
                }
            }
        }

        output.encode_to_vec()
    }

    /// Serialize the full state as a diff from empty.
    /// Mosh: `UserStream::init_diff()`.
    pub fn init_diff(&self) -> Vec<u8> {
        self.diff_from(&UserStream::new())
    }

    /// Apply a serialized diff, appending events to this stream.
    /// Mosh: `UserStream::apply_string(const string &diff)`.
    pub fn apply_string(&mut self, diff: &[u8]) {
        if diff.is_empty() {
            return;
        }
        let input = userinput::UserMessage::decode(diff)
            .expect("UserStream::apply_string failed to decode protobuf");
        for inst in &input.instruction {
            if let Some(ref ks) = inst.keystroke {
                let keys = ks
                    .keys
                    .as_ref()
                    .expect("UserStream::apply_string malformed keystroke");
                for &byte in keys {
                    self.actions.push(UserEvent::Keystroke(byte));
                }
            }
            if let Some(ref r) = inst.resize {
                let w = r.width.expect("UserStream::apply_string malformed resize width");
                let h = r.height.expect("UserStream::apply_string malformed resize height");
                self.actions.push(UserEvent::Resize {
                    width: w,
                    height: h,
                });
            }
            assert!(
                inst.keystroke.is_some() || inst.resize.is_some(),
                "UserStream::apply_string empty instruction"
            );
            if let Some(ref ks) = inst.keystroke {
                if ks.keys.is_none() {
                    panic!("UserStream::apply_string malformed keystroke");
                }
            }
            if let Some(ref r) = inst.resize {
                if r.width.is_none() || r.height.is_none() {
                    panic!("UserStream::apply_string malformed resize");
                }
            }
            if let Some(ref ks) = inst.keystroke {
                if let Some(ref keys) = ks.keys {
                    if keys.is_empty() {
                        // Keep upstream semantics: empty keystroke payload is a no-op.
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_empty() {
        let a = UserStream::new();
        let b = UserStream::new();
        assert!(a.diff_from(&b).is_empty());
    }

    #[test]
    fn test_diff_roundtrip() {
        let mut a = UserStream::new();
        a.push_keystroke(b'h');
        a.push_keystroke(b'i');

        let existing = UserStream::new();
        let diff = a.diff_from(&existing);
        assert!(!diff.is_empty());

        let mut b = UserStream::new();
        b.apply_string(&diff);
        assert_eq!(a, b);
    }

    #[test]
    fn test_diff_incremental() {
        let mut state = UserStream::new();
        state.push_keystroke(b'a');
        state.push_keystroke(b'b');

        let snapshot = state.clone();
        state.push_keystroke(b'c');

        let diff = state.diff_from(&snapshot);
        let mut reconstructed = snapshot.clone();
        reconstructed.apply_string(&diff);
        assert_eq!(state, reconstructed);
    }

    #[test]
    fn test_subtract() {
        let mut state = UserStream::new();
        state.push_keystroke(b'a');
        state.push_keystroke(b'b');
        state.push_keystroke(b'c');

        let mut prefix = UserStream::new();
        prefix.push_keystroke(b'a');
        prefix.push_keystroke(b'b');

        state.subtract(&prefix);
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn test_keystroke_batching() {
        let mut a = UserStream::new();
        a.push_keystroke(b'h');
        a.push_keystroke(b'e');
        a.push_keystroke(b'l');
        a.push_keystroke(b'l');
        a.push_keystroke(b'o');

        let diff = a.init_diff();
        let msg = userinput::UserMessage::decode(diff.as_slice()).unwrap();
        // All keystrokes should be batched into a single instruction
        assert_eq!(msg.instruction.len(), 1);
        assert_eq!(
            msg.instruction[0].keystroke.as_ref().unwrap().keys.as_ref().unwrap(),
            b"hello"
        );
    }

    #[test]
    fn test_resize_breaks_batch() {
        let mut a = UserStream::new();
        a.push_keystroke(b'a');
        a.push_resize(80, 24);
        a.push_keystroke(b'b');

        let diff = a.init_diff();
        let msg = userinput::UserMessage::decode(diff.as_slice()).unwrap();
        // Should be 3 instructions: keystroke, resize, keystroke
        assert_eq!(msg.instruction.len(), 3);
    }

    #[test]
    #[should_panic]
    fn test_diff_panics_when_existing_not_prefix() {
        let mut state = UserStream::new();
        state.push_keystroke(b'a');
        state.push_keystroke(b'b');
        state.push_keystroke(b'c');

        let mut wrong_base = UserStream::new();
        wrong_base.push_keystroke(b'x');

        let _ = state.diff_from(&wrong_base);
    }
}
