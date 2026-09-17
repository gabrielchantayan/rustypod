//! Opaque-record +0x10 word accessor — retailOS `FUN_0820be84` at
//! `0x0820be84` (**8 bytes**).
//!
//! Raw `osos.dec` words establish the complete function: `ldr r0,[r0,#0x10]`
//! at 0x0820be84 and `bx lr` at 0x0820be88. The next separately linked
//! function starts at 0x0820be8c with `str r1,[r0,#0x10]; bx lr`. Decoding
//! inbound ARM branch words finds four plain unconditional `bl` call sites
//! and zero predicated `bl` call sites.
//!
//! Algorithm: return the opaque record's 32-bit word at +0x10 without a NULL
//! guard or other validation. Callers use the value as an argument to
//! unrelated operations, so the record's concrete type and this word's wider
//! meaning are unrecovered.
//!
//! Deliberate deviations: none.

/// Opaque record prefix ending in the observed +0x10 value word.
#[repr(C)]
pub struct OpaqueRecordWordAt10 {
    pub words_before_value: [u32; 4],
    pub value: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(OpaqueRecordWordAt10, value)];

/// opaque_record_word_at_10 — retailOS `FUN_0820be84` at `0x0820be84` (8
/// bytes; 4 direct plain-`bl` call sites, binary-verified).
///
/// # Safety
///
/// `record` must be non-NULL and point to a readable, word-aligned
/// [`OpaqueRecordWordAt10`]. The retailOS load faults for invalid pointers;
/// this port deliberately retains that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_word_at_10")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_word_at_10(record: *const OpaqueRecordWordAt10) -> u32 {
    (*record).value
}

#[cfg(test)]
mod tests {
    use super::{opaque_record_word_at_10, OpaqueRecordWordAt10};

    #[test]
    fn returns_only_the_word_at_offset_10() {
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            let record = OpaqueRecordWordAt10 {
                words_before_value: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00],
                value,
            };

            assert_eq!(unsafe { opaque_record_word_at_10(&record) }, value);
        }
    }
}
