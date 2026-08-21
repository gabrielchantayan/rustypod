//! Cipher-name validation for the proprietary AES-like cipher cluster.
//!
//! The retailOS cipher setup path accepts exactly one standard cipher,
//! identified by the 8-byte name `"STANDARD"` (`s_STANDARD` @ 0x0802e0c4,
//! binary-verified: `53 54 41 4E 44 41 52 44 00` followed by a zero word
//! @ 0x0802e0cc). [`cipher_name_is_standard`] is the gate both callers
//! (0x0802de28, 0x0802e928) run before wiring a key schedule; both test
//! only the low return word.
//!
//! Siblings in the same cluster, ported elsewhere: `block_sub_bytes`
//! 0x0802e118 / ShiftRows-family 0x0802e190+ (in
//! `printf/printf_float_dtoa`, corrected in names.yaml) and
//! `xor_transposed_4x4` 0x0802e54c (in `util/xor_transposed_block`).

use crate::libc::memcmp::memcmp;

/// First word of `s_STANDARD` — `"STAN"` little-endian (0x4E414154).
///
/// The original copies the literal over its own saved-register area, so its
/// `ldmia sp!,{r1,...}` epilogue reloads r1 from the overwritten slot: the
/// high word of the packed return is always this value, success or failure.
const STANDARD_NAME_PREFIX_WORD: u32 = u32::from_le_bytes(*b"STAN");

/// `s_STANDARD` @ 0x0802e0c4 plus the zero word @ 0x0802e0cc — the 12 bytes
/// the original loads with `ldmia r1,{r2,r3,r5}` and stores to its stack
/// frame with `stmia sp,{r2,r3,r5}`. Only the first 8 are ever compared.
const STANDARD_STRING: [u8; 12] = *b"STANDARD\0\0\0\0";

/// Private transcription of the retailOS unguarded strlen
/// (`FUN_08392478` @ 0x08392478): plain byte loop, no NULL guard.
///
/// Deliberately local rather than a call to `crate::libc::strlen` (which is
/// this exact function's port): that module is concurrently in flight by
/// another porter, and this one must not depend on it. `read_volatile`
/// keeps LLVM's loop-idiom pass from rewriting the loop into a libc
/// `strlen` call on the ARM target.
#[inline(never)]
unsafe fn strlen_unguarded(s: *const u8) -> usize {
    let mut p = s;
    let mut len = 0usize;
    while p.read_volatile() != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

/// Outlined so the ARM build keeps the original's `bl` to the ADS memcmp
/// port (@ 0x08030f64) instead of absorbing its body into the validator.
#[inline(never)]
unsafe fn memcmp_standard(name: *const u8, standard: *const u8) -> i32 {
    memcmp(name, standard, 8)
}

/// cipher_name_is_standard — original: `FUN_0802ddcc` @ 0x0802ddcc
/// (72 bytes, 0x0802ddcc..0x0802de14, two `bl` call sites).
///
/// Copies the 12-byte rodata literal `s_STANDARD` ("STANDARD\0" plus the
/// zero word @ 0x0802e0cc) into a stack frame, then measures `name` with
/// the unguarded strlen @ 0x08392478. Unless the length is exactly 8 the
/// compare is skipped and the call fails; otherwise it memcmps the first
/// 8 bytes against the stack copy (ADS memcmp @ 0x08030f64, ported as
/// [`crate::libc::memcmp`]) and succeeds only on equality. Returns a packed
/// 64-bit value: low word 0 on success / 1 on failure, high word always
/// `STANDARD_NAME_PREFIX_WORD` — the `stmia` overwrites the saved r1 slot,
/// so the pop epilogue returns the literal's first four bytes in r1
/// regardless of outcome (Ghidra: `CONCAT44(local_18, uVar2)`). An input
/// of exactly eight non-NUL bytes is accepted only if the byte after the
/// buffer happens to be NUL — the length gate is a real strlen, matching
/// the original's over-read.
///
/// Deviations: the strlen callee is a private byte-loop transcription of
/// 0x08392478 (identical semantics) instead of a call into
/// `crate::libc::strlen`, which another porter owns right now; the packed
/// return is expressed explicitly as a `u64` (r0:r1) rather than relying
/// on the save-slot aliasing trick. Both are codegen-shaping only.
///
/// # Safety
/// `name` must point to a NUL-terminated string (or the scan runs past it,
/// exactly as the original does).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cipher_name_is_standard(name: *const u8) -> u64 {
    // Stack copy of the rodata literal (ldmia r1,{r2,r3,r5} / stmia sp,{r2,r3,r5}).
    let standard_string = STANDARD_STRING;
    let name_length = strlen_unguarded(name);
    let status = if name_length != 8 {
        1u32
    } else if memcmp_standard(name, standard_string.as_ptr()) == 0 {
        0
    } else {
        1
    };
    ((STANDARD_NAME_PREFIX_WORD as u64) << 32) | status as u64
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{cipher_name_is_standard, STANDARD_NAME_PREFIX_WORD};
    use std::vec::Vec;

    /// Packed high word every call must carry: "STAN" little-endian.
    const EXPECTED_HIGH_WORD: u64 = STANDARD_NAME_PREFIX_WORD as u64;

    /// Reference model of the original: strlen up to the first NUL, fail
    /// unless exactly 8, then full 8-byte equality against "STANDARD".
    fn reference_cipher_name_is_standard(name: &[u8]) -> u64 {
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let status = if len != 8 {
            1u64
        } else if &name[..8] == b"STANDARD" {
            0
        } else {
            1
        };
        (EXPECTED_HIGH_WORD << 32) | status
    }

    /// NUL-terminated heap copy so the strlen scan stays in bounds.
    fn terminated(bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(bytes);
        buf.push(0);
        buf
    }

    #[test]
    fn exact_standard_name_succeeds_with_zero_low_word() {
        let name = terminated(b"STANDARD");
        let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
        assert_eq!(packed >> 32, EXPECTED_HIGH_WORD, "high word is \"STAN\"");
        assert_eq!(packed & 0xffff_ffff, 0, "low word 0 on success");
        assert_eq!(packed, EXPECTED_HIGH_WORD << 32);
    }

    /// Trailing bytes after the NUL are never examined — strlen stops at
    /// the first NUL, so "STANDARD\0junk" is still a match.
    #[test]
    fn bytes_after_the_nul_are_not_examined() {
        let mut name = terminated(b"STANDARD");
        name.extend_from_slice(b"junkjunk\xff\x00\x00");
        let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
        assert_eq!(packed & 0xffff_ffff, 0);
    }

    /// Every single-byte mutation of "STANDARD" fails while the length
    /// gate passes; case differences included.
    #[test]
    fn wrong_eight_byte_names_fail() {
        let mut variants: Vec<Vec<u8>> = Vec::new();
        for pos in 0..8usize {
            for delta in [1u8, 0x20] {
                let mut name = *b"STANDARD";
                name[pos] = name[pos].wrapping_add(delta);
                variants.push(terminated(&name));
            }
        }
        variants.push(terminated(b"standard")); // case-sensitive
        for name in &variants {
            let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
            assert_eq!(packed, (EXPECTED_HIGH_WORD << 32) | 1, "{:?}", name);
        }
    }

    /// Length gate: shorter, longer, and empty names all fail without
    /// needing the compare.
    #[test]
    fn names_of_other_lengths_fail() {
        for name in [
            &b""[..],
            b"S",
            b"STANDAR",      // 7
            b"STANDARDX",    // 9
            b"STANDARDSTANDARD",
        ] {
            let name = terminated(name);
            let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
            assert_eq!(packed, (EXPECTED_HIGH_WORD << 32) | 1, "{:?}", name);
        }
    }

    /// Edge consistent with the asm: an eight-byte buffer with no
    /// terminator is judged by whatever byte follows it. A NUL there makes
    /// strlen 8 and the name matches; any other byte makes strlen 9 and
    /// the call fails even though the first 8 bytes equal "STANDARD".
    #[test]
    fn unterminated_eight_byte_buffer_depends_on_the_following_byte() {
        for (follower, expected_status) in [(0u8, 0u64), (b'!', 1), (b'S', 1)] {
            let mut name = Vec::new();
            name.extend_from_slice(b"STANDARD");
            name.push(follower);
            name.push(0); // terminate the scan
            let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
            assert_eq!(
                packed,
                (EXPECTED_HIGH_WORD << 32) | expected_status,
                "follower={follower:#04x}"
            );
        }
    }

    /// The high word is the constant literal prefix on both outcomes —
    /// the original returns it by popping its overwritten save slot.
    #[test]
    fn high_word_is_the_literal_prefix_on_every_outcome() {
        for name in [terminated(b"STANDARD"), terminated(b"NOPENOPE"), terminated(b"")] {
            let packed = unsafe { cipher_name_is_standard(name.as_ptr()) };
            assert_eq!(packed >> 32, EXPECTED_HIGH_WORD);
        }
    }

    /// Exhaustive sweep against the reference model: every length 0..=16
    /// built from a deterministic pattern, plus every single-byte mutation
    /// of the accepted name at every alignment.
    #[test]
    fn matches_reference_across_lengths_and_mutations() {
        for len in 0..=16usize {
            let mut name = Vec::new();
            for i in 0..len {
                name.push(((i as u16 * 37 + 11) % 251) as u8);
            }
            let name = terminated(&name);
            let got = unsafe { cipher_name_is_standard(name.as_ptr()) };
            assert_eq!(got, reference_cipher_name_is_standard(&name), "len={len}");
        }
        for align in 0..4usize {
            for pos in 0..8usize {
                for delta in [1u8, 0x80] {
                    let mut raw = [0xa5u8; 13]; // align + 9 at the max align of 4
                    raw[align..align + 8].copy_from_slice(b"STANDARD");
                    raw[align + pos] ^= delta;
                    raw[align + 8] = 0;
                    let got = unsafe { cipher_name_is_standard(raw.as_ptr().add(align)) };
                    let want = reference_cipher_name_is_standard(&raw[align..]);
                    assert_eq!(
                        got, want,
                        "align={align} pos={pos} delta={delta:#04x}"
                    );
                }
            }
        }
    }

    /// The validator treats its input as read-only.
    #[test]
    fn input_buffer_is_not_modified() {
        let mut name = terminated(b"STANDARD");
        let before = name.clone();
        unsafe { cipher_name_is_standard(name.as_ptr()) };
        assert_eq!(name, before);
    }
}
