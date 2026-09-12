//! `flagged_pair_copy` — retailOS `FUN_081fca6c` at `0x081fca6c` (28 bytes).
//!
//! Raw ARM establishes the true extent as `0x081fca6c..0x081fca88`: seven
//! instructions copy two words and normalize one flag byte; the independent
//! next function begins with `push {r4,lr}` at `0x081fca8c`. Ghidra's 32-byte
//! extent includes the following function's first word. Decoding every ARM
//! B/BL-immediate word in `osos.dec` finds exactly eight direct inbound calls,
//! all unconditional plain `bl` at 0x081b7b10, 0x08214e2c, 0x08214e50,
//! 0x08214e64, 0x083e27ac, 0x083e27c4, 0x083e2818, and 0x083e29d8. There are
//! no predicated forms, direct-B tail callers, or aligned image data words
//! equal to this entry.
//!
//! Algorithm: copy the two opaque target-width words in order, then store the
//! source flag's low bit as a canonical 0 or 1 at +0x08. The record's concrete
//! C++ type is unrecovered, so names describe only its observed layout.
//!
//! Deliberate deviations: volatile accesses pin the retail load/store order,
//! including its forward overlap behavior, and prevent a copy intrinsic.

/// The observed twelve-byte prefix copied by [`flagged_pair_copy`].
///
/// The three bytes after `flag` are outside the original stores and remain
/// untouched in the destination.
#[repr(C)]
pub struct FlaggedPair {
    /// Opaque word at +0x00.
    pub first: u32,
    /// Opaque word at +0x04.
    pub second: u32,
    /// Boolean flag at +0x08; only its low bit is retained by copies.
    pub flag: u8,
    /// Bytes at +0x09..+0x0b, not read or written by this helper.
    pub reserved: [u8; 3],
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(FlaggedPair, first)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(FlaggedPair, second)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(FlaggedPair, flag)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<FlaggedPair>()];

/// flagged_pair_copy — retailOS `FUN_081fca6c` at `0x081fca6c` (28 bytes;
/// eight unconditional plain-`bl` call sites, binary-verified).
///
/// Copies `src.first` and `src.second`, then writes `src.flag & 1` to
/// `dst.flag`. The other three trailing bytes of `dst` are unmodified.
///
/// # Safety
///
/// `dst` must be four-byte aligned and writable through +0x08; `src` must be
/// four-byte aligned and readable through +0x08. Neither pointer is
/// NULL-checked. Overlapping records follow the ARM order: load/store +0x00,
/// load/store +0x04, then load/store +0x08.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.flagged_pair_copy")]
#[inline(never)]
pub unsafe extern "C" fn flagged_pair_copy(dst: *mut FlaggedPair, src: *const FlaggedPair) {
    unsafe {
        let first = core::ptr::addr_of!((*src).first).read_volatile();
        core::ptr::addr_of_mut!((*dst).first).write_volatile(first);
        let second = core::ptr::addr_of!((*src).second).read_volatile();
        core::ptr::addr_of_mut!((*dst).second).write_volatile(second);
        let flag = core::ptr::addr_of!((*src).flag).read_volatile() & 1;
        core::ptr::addr_of_mut!((*dst).flag).write_volatile(flag);
    }
}

#[cfg(test)]
mod tests {
    use super::{flagged_pair_copy, FlaggedPair};

    #[test]
    fn copies_words_normalizes_flag_and_preserves_trailing_bytes() {
        let source = FlaggedPair {
            first: 0x1357_9bdf,
            second: 0x2468_ace0,
            flag: 0xfd,
            reserved: [0x11, 0x22, 0x33],
        };
        let mut destination = FlaggedPair {
            first: 0,
            second: 0,
            flag: 0,
            reserved: [0xa1, 0xb2, 0xc3],
        };

        unsafe { flagged_pair_copy(&mut destination, &source) };

        assert_eq!(destination.first, source.first);
        assert_eq!(destination.second, source.second);
        assert_eq!(destination.flag, 1);
        assert_eq!(destination.reserved, [0xa1, 0xb2, 0xc3]);
    }

    #[test]
    fn clears_destination_flag_when_source_low_bit_is_clear() {
        let source = FlaggedPair {
            first: 0xffff_0000,
            second: 0x0000_ffff,
            flag: 0xfe,
            reserved: [0; 3],
        };
        let mut destination = FlaggedPair {
            first: 0,
            second: 0,
            flag: 0xff,
            reserved: [0; 3],
        };

        unsafe { flagged_pair_copy(&mut destination, &source) };

        assert_eq!(destination.flag, 0);
    }

    #[test]
    fn forward_overlap_exposes_each_store_to_next_load() {
        let mut words: [u32; 4] = [0x1122_3344, 0x5566_7788, 0x99aa_bbfd, 0xdead_bee0];

        unsafe {
            flagged_pair_copy(
                words.as_mut_ptr().add(1).cast::<FlaggedPair>(),
                words.as_ptr().cast::<FlaggedPair>(),
            );
        }

        assert_eq!(words, [0x1122_3344, 0x1122_3344, 0x1122_3344, 0xdead_be00]);
    }
}
