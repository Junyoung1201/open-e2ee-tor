//! Limits, types and validation shared by the o2ee client and server.
//!
//! Every value that crosses the network must be checked against these
//! limits on the receiving side, whichever side that is.

pub mod api;
pub mod container;
pub mod crypto;
pub mod release;
pub mod text;

use std::fmt;

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;

/// Largest plaintext file (or zipped folder) a single transfer may carry.
pub const MAX_FILE_BYTES: u64 = 4 * GIB;
/// Total padded size of transfers waiting in one account's inbox.
pub const MAX_PENDING_BYTES_PER_ACCOUNT: u64 = 8 * GIB;
/// Undelivered transfers are deleted after this long.
pub const TRANSFER_RETENTION_SECS: u64 = 72 * 60 * 60;
/// Ciphertext sizes visible to the server are rounded up to this unit.
pub const PADDING_UNIT_BYTES: u64 = MIB;
/// Unapproved signup requests are deleted after this long.
pub const SIGNUP_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// Signup requests the server keeps waiting at once.
pub const MAX_PENDING_SIGNUPS: usize = 50;
/// A client session (agent) expires after this long.
pub const SESSION_LIFETIME_SECS: u64 = 12 * 60 * 60;

pub const USERNAME_MIN_CHARS: usize = 3;
pub const USERNAME_MAX_CHARS: usize = 32;
pub const SIGNUP_NOTE_MAX_CHARS: usize = 200;

/// Size the server sees for a payload of `len` bytes: at least one padding
/// unit, rounded up to a whole unit. `None` if the padded size overflows.
pub fn padded_len(len: u64) -> Option<u64> {
    let units = len.div_ceil(PADDING_UNIT_BYTES).max(1);
    units.checked_mul(PADDING_UNIT_BYTES)
}

/// A validated account id in canonical (lowercase ASCII) form.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Username(String);

impl Username {
    /// Accepts 3 to 32 ASCII letters or digits. Case is folded so that
    /// `Alice` and `alice` cannot be registered as two different accounts.
    pub fn parse(input: &str) -> Result<Self, InvalidInput> {
        let len = input.chars().count();
        if !(USERNAME_MIN_CHARS..=USERNAME_MAX_CHARS).contains(&len) {
            return Err(InvalidInput::UsernameLength);
        }
        if !input.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(InvalidInput::UsernameCharacters);
        }
        Ok(Self(input.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Optional message from an applicant to the administrator. It is shown on
/// the admin page, so control and bidirectional formatting characters are
/// rejected rather than rendered.
pub fn validate_signup_note(note: &str) -> Result<(), InvalidInput> {
    if note.chars().count() > SIGNUP_NOTE_MAX_CHARS {
        return Err(InvalidInput::NoteLength);
    }
    if note
        .chars()
        .any(|c| c.is_control() || text::is_bidi_control(c))
    {
        return Err(InvalidInput::NoteCharacters);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidInput {
    UsernameLength,
    UsernameCharacters,
    NoteLength,
    NoteCharacters,
}

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UsernameLength => "ID must be 3 to 32 characters",
            Self::UsernameCharacters => "ID may only contain letters and digits",
            Self::NoteLength => "Note must be at most 200 characters",
            Self::NoteCharacters => "Note contains unsupported characters",
        })
    }
}

impl std::error::Error for InvalidInput {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_rounds_up_to_whole_mib() {
        assert_eq!(padded_len(0), Some(MIB));
        assert_eq!(padded_len(1), Some(MIB));
        assert_eq!(padded_len(MIB), Some(MIB));
        assert_eq!(padded_len(MIB + 1), Some(2 * MIB));
        assert_eq!(padded_len(MAX_FILE_BYTES), Some(MAX_FILE_BYTES));
        assert_eq!(padded_len(u64::MAX), None);
    }

    #[test]
    fn username_rules() {
        assert_eq!(
            Username::parse("Alice42").map(|u| u.to_string()),
            Ok("alice42".into())
        );
        assert_eq!(Username::parse("ab"), Err(InvalidInput::UsernameLength));
        assert_eq!(
            Username::parse(&"a".repeat(33)),
            Err(InvalidInput::UsernameLength)
        );
        assert!(Username::parse(&"a".repeat(32)).is_ok());
        for bad in ["al ice", "al_ice", "alice!", "ālice", "аlice"] {
            assert!(Username::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn note_rules() {
        assert!(validate_signup_note("").is_ok());
        assert!(validate_signup_note("안녕하세요, 지문은 메신저로 보냈습니다").is_ok());
        assert!(validate_signup_note(&"가".repeat(200)).is_ok());
        assert_eq!(
            validate_signup_note(&"가".repeat(201)),
            Err(InvalidInput::NoteLength)
        );
        for bad in ["a\nb", "a\u{1b}[31mb", "a\u{202E}b", "a\u{2066}b"] {
            assert_eq!(validate_signup_note(bad), Err(InvalidInput::NoteCharacters));
        }
    }
}
