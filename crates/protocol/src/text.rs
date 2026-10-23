//! Encoding helpers and display sanitising for untrusted strings.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn b64e(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url and rejects anything longer than `max` bytes before
/// allocating for it.
pub fn b64d(text: &str, max: usize) -> Option<Vec<u8>> {
    if text.len() > max.div_ceil(3) * 4 + 4 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (bytes.len() <= max).then_some(bytes)
}

pub fn b64d_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    b64d(text, N)?.try_into().ok()
}

/// Makes a string received from the other side safe to print on a terminal
/// or show in a list: control characters (including ANSI escapes) and
/// bidirectional overrides become `?`, and the result is capped at `max`
/// characters.
pub fn sanitize(input: &str, max: usize) -> String {
    let mut out: String = input
        .chars()
        .take(max)
        .map(|c| {
            if c.is_control() || is_bidi_control(c) {
                '?'
            } else {
                c
            }
        })
        .collect();
    if input.chars().count() > max {
        out.push('…');
    }
    out
}

pub(crate) fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_terminal_controls() {
        assert_eq!(sanitize("bad\u{1b}[2Jname\r\n", 50), "bad?[2Jname??");
        assert_eq!(sanitize("a\u{202E}b", 50), "a?b");
        assert_eq!(sanitize("abcdef", 3), "abc…");
    }

    #[test]
    fn b64_limits() {
        assert_eq!(b64d(&b64e([1u8; 10]), 10), Some(vec![1; 10]));
        assert_eq!(b64d(&b64e([1u8; 11]), 10), None);
        assert_eq!(b64d("!!", 10), None);
        assert_eq!(b64d_array::<4>(&b64e([7u8; 4])), Some([7; 4]));
        assert_eq!(b64d_array::<4>(&b64e([7u8; 3])), None);
    }
}
