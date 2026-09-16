//! `byte_pair_prefix_init` — original: `FUN_083d2384` @ 0x083d2384
//! (44 bytes; **4 unconditional `bl` call sites** targeting it — 0x08269230,
//! 0x08269aa4, 0x083d2164, 0x083d2378 — counted by decoding every ARM BL
//! word in `osos.dec`; the body itself contains **zero** `bl`
//! instructions, conditional or otherwise).
//!
//! Initializes the 8-byte header of a freshly allocated object from two
//! source bytes: `dst[0] = *a`, `dst[1] = *b`, `dst[2] = *a`,
//! `dst[3] = *b` (the low byte of each source word, stored twice), then
//! stores a zero word at `dst[4..8]` and returns `dst` unchanged in `r0`.
//! All four callers pass pointers to two `u32` stack slots as `a`/`b` and
//! a 0x24-byte heap object as `dst` (allocated via the `operator new`-like
//! `FUN_082aadd4`); the callers then store `1.0f` (0x3f800000) at offset 8.
//!
//! The raw body is exactly 11 words from the `ldrb r3, [r1]` at
//! 0x083d2384 through the `bx lr` at 0x083d23ac; 0x083d23b0 begins a new
//! function (`push {r4,r5,r6,r7,r8,lr}`), so Ghidra's 44-byte extent is
//! exact and there is no literal pool.
//!
//! # Deliberate deviations
//!
//! No semantic deviations: the original is a pure load/store leaf, and
//! the port adds no null or bounds validation. The zero word is stored
//! with `write_volatile` so LLVM does not split it into four byte stores.
//! (The raw words `e5d11000`/`e5d21000` have a zero imm12 — they reload
//! `[r1]`/`[r2]` at offset 0, so Ghidra's decompilation is correct that
//! the first byte of each source is duplicated.) LLVM also emits a
//! frame-pointer prologue/epilogue (`push {fp, lr}` / `pop {fp, pc}`)
//! around the otherwise instruction-identical body, and schedules the
//! zero-word store one instruction earlier; `match.py` confirms the
//! load/store core matches the original.

/// Writes the duplicated low-byte header of `dst` from `a` and `b`,
/// zeroes the following word, and returns `dst`.
///
/// # Safety
///
/// `dst` must be writable for 8 bytes; `a` and `b` must be readable for 2
/// bytes each.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_pair_prefix_init(
    dst: *mut u8,
    a: *const u8,
    b: *const u8,
) -> *mut u8 {
    *dst = *a;
    *dst.add(1) = *b;
    *dst.add(2) = *a;
    *dst.add(3) = *b;
    (dst.add(4) as *mut u32).write_volatile(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::byte_pair_prefix_init;

    #[test]
    fn duplicates_low_bytes_and_returns_dst() {
        let a: u32 = 0xdead_beef;
        let b: u32 = 0x1234_5678;
        let mut dst = [0xccu8; 8];
        let ret = unsafe {
            byte_pair_prefix_init(
                dst.as_mut_ptr(),
                &a as *const u32 as *const u8,
                &b as *const u32 as *const u8,
            )
        };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(&dst[..4], &[0xef, 0x78, 0xef, 0x78]);
        assert_eq!(&dst[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn zero_sources_produce_zero_header() {
        let a: u32 = 0;
        let b: u32 = 0;
        let mut dst = [0xffu8; 8];
        unsafe {
            byte_pair_prefix_init(
                dst.as_mut_ptr(),
                &a as *const u32 as *const u8,
                &b as *const u32 as *const u8,
            )
        };
        assert_eq!(dst, [0u8; 8]);
    }

    #[test]
    fn only_low_byte_of_each_source_is_used() {
        // Upper bytes of the sources must not leak into the header.
        let a: u32 = 0xffff_ff01;
        let b: u32 = 0xffff_ff02;
        let mut dst = [0u8; 8];
        unsafe {
            byte_pair_prefix_init(
                dst.as_mut_ptr(),
                &a as *const u32 as *const u8,
                &b as *const u32 as *const u8,
            )
        };
        assert_eq!(&dst[..4], &[0x01, 0x02, 0x01, 0x02]);
    }
}
