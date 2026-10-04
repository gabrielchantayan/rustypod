//! Opaque-record +0x0c word accessor — retailOS `FUN_0829ed44` at
//! `0x0829ed44` and `FUN_0820be94` at `0x0820be94` (**8 bytes each**).
//!
//! Raw words `0xe590000c` and `0xe12fff1e` decode as
//! `ldr r0,[r0,#0xc]; bx lr`. The next real function begins at
//! 0x0820be9c with `stmdb sp!,{r4,r5,r6,lr}`. Whole-image ARM BL
//! decoding finds two plain unconditional inbound calls (0x08280a00 and
//! 0x08280bf0), zero predicated inbound calls, and no calls in this body.
//!
//! Algorithm: return the unchecked 32-bit word at record +0x0c. Both
//! callers pass an embedded record at object +0x3c and forward the result
//! to 0x081c02c0; the field's wider identity is not established. The
//! target's four-byte field spacing is retained on hosts.
//!
//! Deliberate deviations: none.
//!
//! The previously ported 0x0829ed44 entry has the identical two words;
//! its next function starts at 0x0829ed4c (`mov r0,#0x5a; bx lr`).
//! Its four plain inbound BL sites are 0x081a7c50, 0x081efe0c,
//! 0x081efe5c, and 0x081efe94, with no predicated BL sites. Both retailOS
//! entries intentionally share this Rust symbol; no duplicate body or
//! firmware dispatch seam is introduced.

/// Opaque record prefix ending in the observed +0x0c value word.
#[repr(C)]
pub struct OpaqueRecordWordAt0c {
    pub words_before_value: [u32; 3],
    pub value: u32,
}

const _: [u8; 0x0c] = [0; core::mem::offset_of!(OpaqueRecordWordAt0c, value)];

/// Return the word at +0x0c without validation.
///
/// # Safety
///
/// `record` must point to a readable, word-aligned [`OpaqueRecordWordAt0c`].
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
    fn returns_full_word_from_embedded_record_without_changing_storage() {
        #[repr(C)]
        struct Owner {
            prefix: [u32; 15],
            record: OpaqueRecordWordAt0c,
            following_word: u32,
        }

        for value in [0, 1, 0x7fff_ffff, 0x8000_0000, 0x89ab_cdef, u32::MAX] {
            let owner = Owner {
                prefix: [0x1357_2468; 15],
                record: OpaqueRecordWordAt0c {
                    words_before_value: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
                    value,
                },
                following_word: !value,
            };
            assert_eq!(unsafe { opaque_record_word_at_0c(&owner.record) }, value);
            assert_eq!(owner.prefix, [0x1357_2468; 15]);
            assert_eq!(owner.record.words_before_value, [0x1122_3344, 0x5566_7788, 0x99aa_bbcc]);
            assert_eq!(owner.record.value, value);
            assert_eq!(owner.following_word, !value);
        }
    }
}
