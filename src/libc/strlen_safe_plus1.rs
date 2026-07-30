//! NULL-guarded strlen + 1 (C-string buffer size) — original @ 0x08275e20
//! (36 bytes, no functions.csv entry; 51 `bl` call sites binary-scanned).
//!
//! Algorithm: if the pointer is NULL, skip the loop with a count of 0;
//! otherwise walk the string one byte at a time (`ldrb` with
//! post-increment, `addne` on the counter), counting bytes until the NUL
//! terminator. Either way, return count + 1. So a NULL pointer yields 1
//! and any string yields strlen(s) + 1 — the number of bytes needed to
//! hold the string including its NUL terminator.
//!
//! This is the "count+1" variant of strlen_safe @ 0x082770bc listed in
//! its names.yaml entry. Sampled call sites confirm the buffer-size
//! reading: one caller (0x08115678) subtracts 1 from the result to
//! recover the plain length for a bounded copy, and the StringObject
//! sibling @ 0x082a50a0 (`ldr r0,[r0,#4]; b 0x08275e20`) tail-branches
//! here over the string payload to size a copy buffer.
//!
//! Deviation: the byte load is `read_volatile` purely to stop LLVM's
//! loop-idiom pass from recognizing the loop and emitting a call to the
//! (nonexistent) libc `strlen`; codegen stays a byte-at-a-time loop.

/// Returns 1 for a null pointer, else `strlen(s) + 1` — the buffer size
/// needed to hold the C string including its NUL terminator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlen_safe_plus1(s: *const u8) -> usize {
    let mut len = 0usize;
    if !s.is_null() {
        let mut p = s;
        while p.read_volatile() != 0 {
            len += 1;
            p = p.add(1);
        }
    }
    len + 1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Safe reference implementation for parity checks.
    fn ref_strlen_safe_plus1(s: *const u8) -> usize {
        if s.is_null() {
            return 1;
        }
        let mut len = 0;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        len + 1
    }

    #[test]
    fn null_pointer_returns_one() {
        assert_eq!(unsafe { strlen_safe_plus1(core::ptr::null()) }, 1);
    }

    #[test]
    fn empty_string_returns_one() {
        let buf = [0u8; 4];
        assert_eq!(unsafe { strlen_safe_plus1(buf.as_ptr()) }, 1);
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
                let got = unsafe { strlen_safe_plus1(p) };
                assert_eq!(got, ref_strlen_safe_plus1(p), "align={align} len={len}");
                assert_eq!(got, len + 1, "align={align} len={len}");
            }
        }
    }

    /// NUL at each possible early position inside a longer buffer.
    #[test]
    fn stops_at_first_nul() {
        let mut buf = [0xAAu8; 80];
        for nul_pos in 0..64usize {
            buf[nul_pos] = 0;
            assert_eq!(unsafe { strlen_safe_plus1(buf.as_ptr()) }, nul_pos + 1);
            buf[nul_pos] = 0xAA;
        }
    }
}
