//! Ports of the ARM ADS 1.0.1 unaligned-access runtime helpers from osos.
//! The compiler emits calls to these wherever C code dereferences a
//! `__packed`/unaligned u32: they do an explicit byte-wise little-endian
//! assemble/scatter instead of a plain `ldr`/`str` (which would fault or
//! rotate on ARMv5 for misaligned addresses).
//!
//! On modern Rust the same job is `(p as *const u32).read_unaligned()` /
//! `.write_unaligned()`; the byte-wise form is kept deliberately to mirror
//! and document the original idiom.
//!
//! Behavioral verification: host-side `cargo test` compares against a
//! `from_le_bytes`/`to_le_bytes` reference; `tools/match.py` (ipod-decomp)
//! reports the mnemonic-level diff against the original machine code.

/// __rt_uread4 — original: `FUN_08031140` @ 0x08031140 (32 bytes).
///
/// Unaligned little-endian u32 load: reads the four bytes at `p`
/// individually and ORs them together at shifts 0/8/16/24.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_uread4(p: *const u8) -> u32 {
    (*p as u32)
        | ((*p.add(1) as u32) << 8)
        | ((*p.add(2) as u32) << 16)
        | ((*p.add(3) as u32) << 24)
}

/// __rt_uwrite4 — original: `FUN_08031160` @ 0x08031160 (32 bytes).
///
/// Unaligned little-endian u32 store: writes `value` byte by byte at
/// shifts 0/8/16/24 and returns the written value.
///
/// Note: the original's argument registers are (value in r0, p in r1) —
/// i.e. Ghidra sees `__rt_uwrite4(value, p)`. This port takes the more
/// idiomatic Rust order `(p, value)`; the return value matches the original,
/// which leaves `value` untouched in r0 on exit.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_uwrite4(p: *mut u8, value: u32) -> u32 {
    *p = value as u8;
    *p.add(1) = (value >> 8) as u8;
    *p.add(2) = (value >> 16) as u8;
    *p.add(3) = (value >> 24) as u8;
    value
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn ref_uread4(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    fn ref_uwrite4(buf: &mut [u8], off: usize, value: u32) -> u32 {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        value
    }

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16) % 251) as u8).collect()
    }

    /// Read at every alignment 0..3 and beyond, over patterned buffers.
    #[test]
    fn uread4_matches_reference_all_alignments() {
        for size in [8usize, 16, 64] {
            let buf = pattern(size, 37);
            for off in 0..=size - 4 {
                let got = unsafe { __rt_uread4(buf.as_ptr().add(off)) };
                assert_eq!(got, ref_uread4(&buf, off), "mismatch: size={size} off={off}");
            }
        }
    }

    /// Interesting values: zero, all-ones, single-byte lanes, mixed.
    #[test]
    fn uread4_interesting_values() {
        for value in [
            0x00000000u32,
            0xffffffff,
            0x000000ff,
            0x0000ff00,
            0x00ff0000,
            0xff000000,
            0x01020304,
            0xdeadbeef,
            0x80000000,
            0x00000001,
        ] {
            let buf = value.to_le_bytes();
            for off in 0..4usize {
                // Shift the 4 data bytes through a padded buffer to vary alignment.
                let mut padded = vec![0xaau8; 8];
                padded[off..off + 4].copy_from_slice(&buf);
                let got = unsafe { __rt_uread4(padded.as_ptr().add(off)) };
                assert_eq!(got, value, "mismatch: value={value:#010x} off={off}");
            }
        }
    }

    /// Write at every alignment 0..3 and beyond: bytes land in LE order,
    /// surrounding bytes are untouched, and the value is returned.
    #[test]
    fn uwrite4_matches_reference_all_alignments() {
        for size in [8usize, 16, 64] {
            for off in 0..=size - 4 {
                let mut orig = pattern(size, 91);
                let mut reference = orig.clone();
                let value = (off as u32).wrapping_mul(0x01010101) ^ 0x5a5a5a5a;
                let ret = unsafe { __rt_uwrite4(orig.as_mut_ptr().add(off), value) };
                assert_eq!(ret, ref_uwrite4(&mut reference, off, value));
                assert_eq!(orig, reference, "mismatch: size={size} off={off}");
            }
        }
    }

    /// Interesting values through the write path, checking return value too.
    #[test]
    fn uwrite4_interesting_values() {
        for value in [
            0x00000000u32,
            0xffffffff,
            0x000000ff,
            0x0000ff00,
            0x00ff0000,
            0xff000000,
            0x01020304,
            0xdeadbeef,
            0x80000000,
            0x00000001,
        ] {
            for off in 0..4usize {
                let mut buf = vec![0xaau8; 8];
                let ret = unsafe { __rt_uwrite4(buf.as_mut_ptr().add(off), value) };
                assert_eq!(ret, value);
                assert_eq!(&buf[off..off + 4], value.to_le_bytes().as_slice());
                // Sentinel bytes outside the 4-byte window must survive.
                assert!(buf[..off].iter().all(|&b| b == 0xaa));
                assert!(buf[off + 4..].iter().all(|&b| b == 0xaa));
            }
        }
    }

    /// Round-trip: write then read back at the same unaligned offset.
    #[test]
    fn write_then_read_roundtrip() {
        let mut buf = vec![0u8; 68];
        for off in 0..64usize {
            let value = 0xc0ffee00u32 ^ (off as u32).wrapping_mul(2654435761);
            unsafe {
                let base = buf.as_mut_ptr().add(off);
                assert_eq!(__rt_uwrite4(base, value), value);
                assert_eq!(__rt_uread4(base), value);
            }
        }
    }
}
