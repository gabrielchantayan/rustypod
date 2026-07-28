//! Unaligned little-endian load family @ 0x080ed738 / 0x080ed748 / 0x080ed768.
//!
//! Three pure leaf functions that assemble a 16/32/64-bit little-endian
//! value out of individual `ldrb`s. They are the ARM ADS idiom for
//! dereferencing a `__packed` (unaligned) integer: a plain `ldr`/`ldrh` at
//! a misaligned address on the ARM926EJ-S rotates the loaded word instead
//! of faulting, so the compiler outlines a byte-wise reader instead.
//!
//! This is a *second* copy of that runtime family — `__rt_uread4`
//! @ 0x08031140 (see `libc/rt_unaligned.rs`) does the same job for the
//! 32-bit case. The two differ only in codegen: 0x08031140 uses fixed
//! offsets and returns with `mov pc, lr`, while this cluster uses
//! post-indexed `ldrb`s and returns with `bx lr` (interworking-safe), i.e.
//! it came from a different object file / compiler invocation. Behavior is
//! identical, so the ports are behaviorally interchangeable; both addresses
//! are kept so hooks can target either call graph.
//!
//! Because the two 32-bit bodies really are identical, LLVM folds
//! `read_u32_le` onto `__rt_uread4`: the archive exports both symbols at
//! the same address in the same section. That is harmless (a hook branching
//! to either lands on correct code) but it means `tools/match.py 0x080ed748
//! read_u32_le` finds no separate body — review it as
//! `match.py 0x080ed748 __rt_uread4` instead.
//!
//! Sizes from decomp/functions.csv; call-site counts from decoding every
//! `b`/`bl` word in osos.dec (osos.asm drops lines and undercounts):
//!
//! - `read_u16_le` — `FUN_080ed738` @ 0x080ed738 (16 bytes; 34 call sites).
//! - `read_u32_le` — `FUN_080ed748` @ 0x080ed748 (32 bytes; 66 call sites).
//! - `read_u64_le` — `FUN_080ed768` @ 0x080ed768 (88 bytes; 2 call sites).
//!
//! All three are leaves and touch no hardware, so host tests prove complete
//! behavior against a `from_le_bytes` reference.
//!
//! A note on the 64-bit case: the original's first half contains four
//! provably-dead instructions —
//! `lsr r2, r1, #24` / `lsr r3, r1, #16` / `orr r2, r3, r2` /
//! `orr r1, r2, ip, lsr #8`. They are the *high* words of the 64-bit shifts
//! `((u64)p[1] << 8)`, `((u64)p[2] << 16)`, `((u64)p[3] << 24)`, which ADS
//! emitted mechanically without noticing that a zero-extended byte shifted
//! left by less than 32 can never reach bit 32. Each of those terms is
//! always zero, so the port drops them; the returned value is unchanged.

/// read_u16_le — original: `FUN_080ed738` @ 0x080ed738 (16 bytes).
///
/// Unaligned little-endian u16 load: `p[0] | p[1] << 8`, zero-extended to
/// the full return register (the original leaves r0's top half clear
/// because both operands are `ldrb`s).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_u16_le(p: *const u8) -> u32 {
    (*p as u32) | ((*p.add(1) as u32) << 8)
}

/// read_u32_le — original: `FUN_080ed748` @ 0x080ed748 (32 bytes).
///
/// Unaligned little-endian u32 load: the four bytes at `p` ORed together at
/// shifts 0/8/16/24.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_u32_le(p: *const u8) -> u32 {
    (*p as u32)
        | ((*p.add(1) as u32) << 8)
        | ((*p.add(2) as u32) << 16)
        | ((*p.add(3) as u32) << 24)
}

/// read_u64_le — original: `FUN_080ed768` @ 0x080ed768 (88 bytes).
///
/// Unaligned little-endian u64 load: the eight bytes at `p` ORed together
/// at shifts 0..56. The original returns the low word in r0 and the high
/// word in r1, exactly the AAPCS 64-bit return convention, and builds them
/// as two independent 32-bit assemblies — the port keeps that shape.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_u64_le(p: *const u8) -> u64 {
    let low = read_u32_le(p);
    let high = read_u32_le(p.add(4));
    ((high as u64) << 32) | (low as u64)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8).collect()
    }

    /// Every alignment 0..3 (and beyond) over a patterned buffer, against
    /// `u16::from_le_bytes`.
    #[test]
    fn read_u16_le_matches_reference() {
        let buf = pattern(64, 37);
        for off in 0..=buf.len() - 2 {
            let want = u16::from_le_bytes([buf[off], buf[off + 1]]) as u32;
            assert_eq!(unsafe { read_u16_le(buf.as_ptr().add(off)) }, want, "off={off}");
        }
    }

    #[test]
    fn read_u32_le_matches_reference() {
        let buf = pattern(64, 91);
        for off in 0..=buf.len() - 4 {
            let want = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            assert_eq!(unsafe { read_u32_le(buf.as_ptr().add(off)) }, want, "off={off}");
        }
    }

    #[test]
    fn read_u64_le_matches_reference() {
        let buf = pattern(64, 113);
        for off in 0..=buf.len() - 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[off..off + 8]);
            assert_eq!(
                unsafe { read_u64_le(buf.as_ptr().add(off)) },
                u64::from_le_bytes(bytes),
                "off={off}"
            );
        }
    }

    /// Extremes and single-lane values, placed at every alignment.
    #[test]
    fn interesting_values_at_every_alignment() {
        for value in [
            0x0000_0000_0000_0000u64,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_0000_0001,
            0x8000_0000_0000_0000,
            0x0102_0304_0506_0708,
            0xdead_beef_cafe_f00d,
            0x00ff_00ff_00ff_00ff,
        ] {
            for off in 0..4usize {
                let mut padded = vec![0xa5u8; 16];
                padded[off..off + 8].copy_from_slice(&value.to_le_bytes());
                let base = padded.as_ptr();
                unsafe {
                    assert_eq!(read_u64_le(base.add(off)), value, "u64 {value:#018x} off={off}");
                    assert_eq!(read_u32_le(base.add(off)), value as u32, "u32 off={off}");
                    assert_eq!(read_u16_le(base.add(off)), value as u16 as u32, "u16 off={off}");
                }
            }
        }
    }

    /// The readers must not touch a byte outside their width — a violation
    /// would show up as a mismatch when the neighbours differ.
    #[test]
    fn readers_stay_within_their_width() {
        let mut buf = [0xffu8; 12];
        buf[4] = 0x11;
        buf[5] = 0x22;
        buf[6] = 0x33;
        buf[7] = 0x44;
        let p = unsafe { buf.as_ptr().add(4) };
        unsafe {
            assert_eq!(read_u16_le(p), 0x2211);
            assert_eq!(read_u32_le(p), 0x4433_2211);
        }
    }

    /// The 64-bit reader is exactly its two 32-bit halves — this is the
    /// property the original's dead high-word terms would have broken had
    /// they been nonzero.
    #[test]
    fn read_u64_le_is_two_read_u32_le_halves() {
        let buf = pattern(32, 53);
        for off in 0..=buf.len() - 8 {
            unsafe {
                let base = buf.as_ptr().add(off);
                let expect = ((read_u32_le(base.add(4)) as u64) << 32) | read_u32_le(base) as u64;
                assert_eq!(read_u64_le(base), expect, "off={off}");
            }
        }
    }
}
