//! The length-prefix field encoder shared by every signed canonical in this
//! crate: `<decimal byte-length>:<bytes>\n`.
//!
//! Length prefixes (not delimiters) make field composition injection-safe: a
//! field containing `:` or `\n` cannot forge a different field split, so no
//! two distinct tuples can serialize to the same bytes.

/// Append one length-prefixed field to `out`.
pub fn lp_push(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s.as_bytes());
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::lp_push;

    #[test]
    fn encodes_length_colon_bytes_newline() {
        let mut out = Vec::new();
        lp_push(&mut out, "ab");
        lp_push(&mut out, "");
        lp_push(&mut out, "x:y\n");
        assert_eq!(out, b"2:ab\n0:\n4:x:y\n\n");
    }
}
