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
//! A *third* copy of the 32-bit reader lives at 0x0839e7e8 with a
//! base-plus-offset signature — the caller keeps the record base in r0 and
//! passes the field offset in r1. The body is the same four-byte assembly,
//! so LLVM folds it onto `__rt_uread4` too; review it as
//! `match.py 0x0839e7e8 __rt_uread4`.
//!
//! Sizes from decomp/functions.csv; call-site counts from decoding every
//! `b`/`bl` word in osos.dec (osos.asm drops lines and undercounts):
//!
//! - `read_u16_le` — `FUN_080ed738` @ 0x080ed738 (16 bytes; 34 call sites).
//! - `read_u32_le` — `FUN_080ed748` @ 0x080ed748 (32 bytes; 66 call sites).
//! - `read_u64_le` — `FUN_080ed768` @ 0x080ed768 (88 bytes; 2 call sites).
//! - `read_u32_le_at` — `FUN_0839e7e8` @ 0x0839e7e8 (36 bytes; 4 call sites).
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

/// read_u32_le_at — original: `FUN_0839e7e8` @ 0x0839e7e8 (36 bytes).
///
/// Unaligned little-endian u32 load at a caller-supplied offset:
/// `*(u32 *)(base + offset)` assembled byte-wise, identical in behavior to
/// `read_u32_le(base.add(offset))`. The original loads byte 0 with
/// `ldrb r2, [r0, r1]`, advances `r0` by `offset`, then gathers bytes 1..3
/// at fixed offsets and ORs everything into the return register; 36 bytes,
/// 9 instructions, ends in `bx lr` with the next function's
/// `push {r4,r5,r6,lr}` at 0x0839e80c. 4 plain `bl` call sites
/// (0x081608a0/0x081608ec/0x08160958/0x081609d0), 0 predicated, 0 plain
/// `b` — binary-scanned.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read_u32_le_at(base: *const u8, offset: u32) -> u32 {
    let p = base.add(offset as usize);
    (*p as u32)
        | ((*p.add(1) as u32) << 8)
        | ((*p.add(2) as u32) << 16)
        | ((*p.add(3) as u32) << 24)
}

/// store_u32_le_at — original: `FUN_0839e7c4` @ 0x0839e7c4 (36 bytes).
///
/// Writes `value` as four unaligned little-endian bytes at `base + offset`.
/// Raw ARM establishes the exact extent 0x0839e7c4..0x0839e7e8: `strb`
/// byte 0 at the register-indexed address, advances r0 by `offset`, then
/// stores bytes 1..3 at fixed offsets and returns with `bx lr`. Three plain
/// `bl` callers (0x081609b4/0x081609c4/0x081609ec), no predicated `bl`
/// callers. Deliberate deviations: volatile stores preserve the observed ARM
/// store order; the source-level return is the advanced destination pointer,
/// preserving r0 even though the C decompilation inferred `void`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn store_u32_le_at(base: *mut u8, offset: u32, value: u32) -> *mut u8 {
    let dst = base.add(offset as usize);
    dst.write_volatile(value as u8);
    dst.add(1).write_volatile((value >> 8) as u8);
    dst.add(2).write_volatile((value >> 16) as u8);
    dst.add(3).write_volatile((value >> 24) as u8);
    dst
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

    /// The offset form must agree with `read_u32_le(base.add(offset))`
    /// over offsets 0 and every alignment, including straddling the end of
    /// the buffer's patterned region.
    #[test]
    fn read_u32_le_at_matches_pointer_form() {
        let buf = pattern(64, 73);
        for off in 0..=buf.len() - 4 {
            let want = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            assert_eq!(
                unsafe { read_u32_le_at(buf.as_ptr(), off as u32) },
                want,
                "off={off}"
            );
            assert_eq!(
                unsafe { read_u32_le_at(buf.as_ptr(), off as u32) },
                unsafe { read_u32_le(buf.as_ptr().add(off)) },
                "pointer-form off={off}"
            );
        }
    }

    /// Offset zero reads from the base itself; a nonzero offset must not
    /// leak base bytes into the result.
    #[test]
    fn read_u32_le_at_zero_and_extremes() {
        let buf = [0x78, 0x56, 0x34, 0x12, 0xde, 0xad, 0xbe, 0xef];
        unsafe {
            assert_eq!(read_u32_le_at(buf.as_ptr(), 0), 0x1234_5678);
            assert_eq!(read_u32_le_at(buf.as_ptr(), 4), 0xefbe_adde);
        }
        for value in [0u32, u32::MAX, 1, 0x8000_0000, 0x0102_0304] {
            let bytes = value.to_le_bytes();
            assert_eq!(unsafe { read_u32_le_at(bytes.as_ptr(), 0) }, value);
        }
    }

    #[test]
    fn store_u32_le_at_writes_only_four_little_endian_bytes_at_each_alignment() {
        for value in [0, u32::MAX, 1, 0x8000_0000, 0x0102_0304, 0xdead_beef] {
            for offset in 0..4usize {
                let mut bytes = [0xa5; 12];
                let returned = unsafe {
                    store_u32_le_at(bytes.as_mut_ptr(), offset as u32, value)
                };
                assert_eq!(returned, unsafe { bytes.as_mut_ptr().add(offset) });
                assert_eq!(&bytes[offset..offset + 4], value.to_le_bytes());
                assert!(bytes[..offset].iter().all(|&byte| byte == 0xa5));
                assert!(bytes[offset + 4..].iter().all(|&byte| byte == 0xa5));
            }
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
