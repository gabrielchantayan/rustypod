//! Opaque-record +0x0c word accessor — retailOS `FUN_0829ed44` at
//! `0x0829ed44` (**8 bytes**).
//!
//! Raw ARM establishes the exact extent: `ldr r0,[r0,#0xc]; bx lr`. The next
//! real function begins at `0x0829ed4c` with `mov r0,#0x5a; bx lr`. Decoding
//! every aligned ARM B/BL-immediate word in `osos.dec` finds **4** inbound
//! sites, all unconditional plain `bl` (at `0x081a7c50`, `0x081efe0c`,
//! `0x081efe5c`, and `0x081efe94`); no predicated `bl` reaches this entry.
//!
//! Algorithm: return the opaque record's 32-bit word at +0x0c without a NULL
//! guard or other validation. The record's concrete type and the word's wider
//! meaning are unrecovered, so its name states only the verified layout.
//!
//! Deliberate deviations: none.

/// Opaque record prefix ending in the observed +0x0c value word.
#[repr(C)]
pub struct OpaqueRecordWordAt0c {
    pub words_before_value: [u32; 3],
    pub value: u32,
}

const _: [u8; 0x0c] = [0; core::mem::offset_of!(OpaqueRecordWordAt0c, value)];

/// opaque_record_word_at_0c — retailOS `FUN_0829ed44` at `0x0829ed44` (8
/// bytes; 4 direct plain-`bl` call sites, binary-verified).
///
/// # Safety
///
/// `record` must be non-NULL and point to a readable, word-aligned
/// [`OpaqueRecordWordAt0c`]. The retailOS load faults for invalid pointers;
/// this port deliberately retains that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_word_at_0c")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_word_at_0c(record: *const OpaqueRecordWordAt0c) -> u32 {
    (*record).value
}

#[cfg(test)]
mod tests {
    use super::{opaque_record_word_at_0c, OpaqueRecordWordAt0c};

    #[test]
    fn returns_only_the_word_at_offset_0c() {
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            let record = OpaqueRecordWordAt0c {
                words_before_value: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
                value,
            };

            assert_eq!(unsafe { opaque_record_word_at_0c(&record) }, value);
        }
    }
}
