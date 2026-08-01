//! strlen — original: `FUN_08392478` @ 0x08392478 (32 bytes, 419 `bl` call
//! sites, binary-scanned).
//!
//! The unguarded retailOS strlen: no NULL check, no word-at-a-time trick,
//! just `ldrb`/`cmp`/`add` until the NUL. It is the sibling of `strcmp`
//! @ 0x08391e44 in the same plain byte-loop string cluster, and is a
//! *different* function from the NULL-guarded `strlen_safe` @ 0x082770bc
//! (which two other modules already inline as `strlen_raw`; those copies
//! stay put — they are `strlen_safe` call sites, not this one).
//!
//! Counter accumulation in the original is separate from the pointer walk
//! (`addne r1, r1, #1` / `addne r0, r0, #1`), returning the count in r0 as
//! a plain `int`.
//!
//! Deviation: `read_volatile` for the byte load, so LLVM's loop-idiom pass
//! cannot turn the loop into a call to `strlen` — which here would be a
//! call to this very function.

/// Length of the NUL-terminated string at `s`. No NULL guard, matching the
/// original — original @ 0x08392478.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut p = s;
    let mut len = 0usize;
    while p.read_volatile() != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

/// `strlen_byte_loop` — original: `FUN_08044190` @ 0x08044190 (32 bytes).
///
/// Independent unguarded byte-at-a-time NUL scan: copy the input pointer,
/// load one unsigned byte, and advance both the pointer and 32-bit count
/// only while that byte is nonzero. The terminator is read but not advanced
/// past. `read_volatile` keeps LLVM from recognizing the loop as a libc
/// `strlen` call; this is distinct from the ADS `strlen` at 0x08392478.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlen_byte_loop(s: *const u8) -> u32 {
    let mut p = s;
    let mut len = 0u32;
    while p.read_volatile() != 0 {
        p = p.add(1);
        len = len.wrapping_add(1);
    }
    len
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn ref_strlen(s: &[u8]) -> usize {
        s.iter().position(|&b| b == 0).expect("NUL-terminated")
    }

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(unsafe { strlen(b"\0".as_ptr()) }, 0);
    }

    #[test]
    fn counts_bytes_before_nul() {
        assert_eq!(unsafe { strlen(b"a\0".as_ptr()) }, 1);
        assert_eq!(unsafe { strlen(b"hello\0".as_ptr()) }, 5);
        assert_eq!(unsafe { strlen(b"hello\0world\0".as_ptr()) }, 5);
    }

    /// High bytes are not terminators (`ldrb`, unsigned).
    #[test]
    fn high_bytes_are_not_terminators() {
        assert_eq!(unsafe { strlen(b"\x80\xff\x7f\0".as_ptr()) }, 3);
    }

    /// Every length 0..64 at every start alignment 0..3.
    #[test]
    fn matches_reference_all_lengths_and_alignments() {
        for align in 0..4usize {
            let mut buf: Vec<u8> = std::vec![0u8; align + 64 + 1];
            for len in 0..64usize {
                for i in 0..len {
                    buf[align + i] = (i as u8 % 251) + 1;
                }
                buf[align + len] = 0;
                let got = unsafe { strlen(buf.as_ptr().add(align)) };
                assert_eq!(got, ref_strlen(&buf[align..]), "align={align} len={len}");
                assert_eq!(got, len, "align={align} len={len}");
            }
        }
    }

    fn ref_strlen_byte_loop(s: &[u8]) -> u32 {
        s.iter()
            .position(|&b| b == 0)
            .expect("NUL-terminated") as u32
    }

    #[test]
    fn byte_loop_empty_string_returns_zero() {
        let buf = [0u8; 1];
        assert_eq!(
            unsafe { strlen_byte_loop(buf.as_ptr()) },
            ref_strlen_byte_loop(&buf)
        );
    }

    /// Every length 0..64 at every start alignment 0..3, checked against an
    /// independent slice reference. The scan must stop at the first NUL.
    #[test]
    fn byte_loop_matches_reference_all_lengths_and_alignments() {
        for align in 0..4usize {
            let mut buf: Vec<u8> = std::vec![0u8; align + 64 + 2];
            for len in 0..64usize {
                for i in 0..len {
                    buf[align + i] = (i as u8 % 251) + 1;
                }
                buf[align + len] = 0;
                buf[align + len + 1] = 0x80;
                let input = &buf[align..];
                let got = unsafe { strlen_byte_loop(input.as_ptr()) };
                assert_eq!(got, ref_strlen_byte_loop(input), "align={align} len={len}");
                assert_eq!(got, len as u32, "align={align} len={len}");
            }
        }
    }
}
