//! NULL-guarded strlen — original @ 0x082770bc (36 bytes, no functions.csv
//! entry; the classic ADS word-optimized strlen is absent from this binary,
//! so retailOS calls this helper instead).
//!
//! Algorithm: return 0 for a null pointer, otherwise walk the string one
//! byte at a time (`ldrb` with post-increment), counting bytes until the
//! NUL terminator. There is no word-at-a-time trick to port — the original
//! is a plain byte loop, so the Rust port is a direct transcription.
//!
//! Deviation: the byte load is `read_volatile` purely to stop LLVM's
//! loop-idiom pass from recognizing the loop and emitting a call to the
//! (nonexistent) libc `strlen`; codegen stays a byte-at-a-time loop.

/// Returns 0 for a null pointer, else the number of bytes before the first
/// NUL byte (i.e. a NULL-safe `strlen`).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlen_safe(s: *const u8) -> usize {
    let mut len = 0usize;
    if !s.is_null() {
        let mut p = s;
        while p.read_volatile() != 0 {
            len += 1;
            p = p.add(1);
        }
    }
    len
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Safe reference implementation for parity checks.
    fn ref_strlen_safe(s: *const u8) -> usize {
        if s.is_null() {
            return 0;
        }
        let mut len = 0;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        len
    }

    #[test]
    fn null_pointer_returns_zero() {
        assert_eq!(unsafe { strlen_safe(core::ptr::null()) }, 0);
    }

    #[test]
    fn empty_string_returns_zero() {
        let buf = [0u8; 4];
        assert_eq!(unsafe { strlen_safe(buf.as_ptr()) }, 0);
    }

    /// Every length 0..64 at every start alignment 0..3, checked against
    /// the reference. Buffer is padded so the pointer arithmetic stays in
    /// bounds regardless of alignment.
    #[test]
    fn matches_reference_all_lengths_and_alignments() {
        for align in 0..4usize {
            let mut buf: Vec<u8> = std::vec![0u8; align + 64 + 1];
            for len in 0..64usize {
                for i in 0..len {
                    buf[align + i] = (i as u8 % 251) + 1; // non-NUL payload
                }
                buf[align + len] = 0;
                let p = unsafe { buf.as_ptr().add(align) };
                let got = unsafe { strlen_safe(p) };
                assert_eq!(got, ref_strlen_safe(p), "align={align} len={len}");
                assert_eq!(got, len, "align={align} len={len}");
            }
        }
    }

    /// NUL at each possible early position inside a longer buffer.
    #[test]
    fn stops_at_first_nul() {
        let mut buf = [0xAAu8; 80];
        for nul_pos in 0..64usize {
            buf[nul_pos] = 0;
            assert_eq!(unsafe { strlen_safe(buf.as_ptr()) }, nul_pos);
            buf[nul_pos] = 0xAA;
        }
    }
}
