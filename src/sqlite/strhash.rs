//! SQLite's `strHash` for `SQLITE_HASH_NOCASE` — the table-driven byte
//! hash behind the engine's case-insensitive hash tables (hash.c).
//!
//! Ported here:
//!
//! - `string_hash_tabled` — original: `FUN_08391dec` @ 0x08391dec
//!   (72 bytes; 3 `bl` call sites per the scouting note — none resolve
//!   in the osos.asm text, so the hash is likely reached through a
//!   function pointer in the `Hash`/`HashElem` machinery).
//!
//! The fold table is the same `sqlite3UpperToLower` the comparisons in
//! [`super::stricmp`] use (runtime 0x088faa8b, image 0x08905963 — the
//! +0xaed8 skew documented in [`super`]); the literal pool word at
//! 0x08391e34 points at it.
//!
//! Algorithm, from the assembly: `h` starts at 0; for each of `len`
//! bytes, `h = table[c] ^ h ^ (h << 3)` (`ldrb` / `eor r2, r5, r5,
//! lsl #3` / `eor r5, r1, r2`); the result is returned with the top bit
//! cleared (`bic r0, r5, #0x80000000`). A `len <= 0` first measures the
//! string with the unguarded strlen @ 0x08392478, so a negative budget
//! hashes a NUL-terminated string and `len == 0` is *not* "hash
//! nothing" — it is the probe for the common call. The byte count is
//! re-tested after the strlen (`b 0x08391e24` into the `cmp`/`bgt`),
//! so an empty string still returns 0.
//!
//! Deviation: LLVM inlines the strlen call (the `cxx/string.rs`
//! precedent) — match.py shows a byte-scan prefix loop instead of the
//! original's `bl 0x08392478`; the hash loop itself matches
//! instruction-for-instruction up to XOR operand order.

use super::stricmp::UPPER_TO_LOWER;
use crate::libc::strlen::strlen;

/// string_hash_tabled — original: `FUN_08391dec` @ 0x08391dec
/// (72 bytes).
///
/// Hashes `len` bytes of `s` as `h = fold(c) ^ h ^ (h << 3)`, returning
/// `h & 0x7fffffff`. `len <= 0` hashes the whole NUL-terminated string
/// instead.
///
/// # Safety
/// `s` must point at `len` readable bytes — or, when `len <= 0`, at a
/// NUL-terminated string (the unguarded strlen reads to the terminator).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_hash_tabled(s: *const u8, len: i32) -> u32 {
    let mut remaining = len;
    if remaining <= 0 {
        remaining = strlen(s) as i32;
    }
    let mut cursor = s;
    let mut h: u32 = 0;
    while remaining > 0 {
        let byte = cursor.read_volatile();
        cursor = cursor.add(1);
        h = UPPER_TO_LOWER[byte as usize] as u32 ^ h ^ h.wrapping_shl(3);
        remaining -= 1;
    }
    h & 0x7fff_ffff
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// The loop transcribed straight from the assembly, independently of
    /// the port's structure.
    fn reference(s: &[u8], len: i32) -> u32 {
        let mut remaining = len;
        if remaining <= 0 {
            remaining = s.iter().position(|&b| b == 0).unwrap() as i32;
        }
        let mut h: u32 = 0u32;
        let mut i = 0usize;
        while remaining > 0 {
            let c = s[i];
            i += 1;
            let folded = if c.is_ascii_uppercase() { c + 0x20 } else { c };
            h = folded as u32 ^ h ^ h.wrapping_shl(3);
            remaining -= 1;
        }
        h & 0x7fff_ffff
    }

    #[test]
    fn empty_and_shorter_than_nul_prefixes() {
        unsafe {
            assert_eq!(string_hash_tabled(b"\0".as_ptr(), -1), 0);
            assert_eq!(string_hash_tabled(b"\0".as_ptr(), 0), 0);
            assert_eq!(string_hash_tabled(b"a\0".as_ptr(), 1), 'a' as u32);
            assert_eq!(string_hash_tabled(b"abc\0".as_ptr(), 2), reference(b"abc\0", 2));
        }
    }

    #[test]
    fn uppercase_folds_to_lowercase() {
        unsafe {
            let lower = string_hash_tabled(b"select\0".as_ptr(), -1);
            let upper = string_hash_tabled(b"SELECT\0".as_ptr(), -1);
            let mixed = string_hash_tabled(b"SeLeCt\0".as_ptr(), 6);
            assert_eq!(lower, upper);
            assert_eq!(lower, mixed);
        }
    }

    #[test]
    fn non_ascii_bytes_pass_through_unfolded() {
        unsafe {
            let a = string_hash_tabled(b"\x80\xff\0".as_ptr(), -1);
            let b = string_hash_tabled([0x80u8, 0xff, 0].as_ptr(), 2);
            assert_eq!(a, b);
            assert_eq!(a, reference(&[0x80, 0xff, 0], 2));
        }
    }

    #[test]
    fn matches_the_reference_over_a_sweep() {
        // Every byte value, lengths 0..64, both the explicit-length and
        // the strlen-probe paths; the buffer is NUL-free except at the
        // terminator so the two paths must agree.
        let mut buf: Vec<u8> = (1u8..=255).cycle().take(256).collect();
        buf.push(0);
        unsafe {
            for len in 0..64usize {
                let explicit = string_hash_tabled(buf.as_ptr(), len as i32);
                assert_eq!(explicit, reference(&buf, len as i32), "len {len}");
            }
            for term in 1..64usize {
                let saved = buf[term];
                buf[term] = 0;
                let probed = string_hash_tabled(buf.as_ptr(), -1);
                assert_eq!(probed, reference(&buf[..=term], -1), "term {term}");
                buf[term] = saved;
            }
        }
    }

    #[test]
    fn the_top_bit_is_always_cleared() {
        unsafe {
            // Drive h through values with the top bit set.
            for first in 0u32..256 {
                let buf = [first as u8, 0];
                assert_eq!(string_hash_tabled(buf.as_ptr(), -1) >> 31, 0, "byte {first:#x}");
            }
            let long: Vec<u8> = (0u8..=255).chain(0u8..=255).collect();
            assert_eq!(string_hash_tabled(long.as_ptr(), 512) >> 31, 0);
        }
    }

    #[test]
    fn known_sqlite_vectors() {
        // strHash("xyz") computed by hand from the recurrence:
        // h0 = 'x' = 0x78
        // h1 = 'y' ^ h0 ^ (h0<<3) = 0x79 ^ 0x78 ^ 0x3c0 = 0x3c1
        // h2 = 'z' ^ h1 ^ (h1<<3)
        let h1 = 0x79u32 ^ 0x78 ^ (0x78u32 << 3);
        let h2 = 0x7au32 ^ h1 ^ (h1 << 3);
        unsafe {
            assert_eq!(string_hash_tabled(b"xyz\0".as_ptr(), -1), h2 & 0x7fff_ffff);
            assert_eq!(string_hash_tabled(b"XYZ\0".as_ptr(), -1), h2 & 0x7fff_ffff);
        }
    }
}
