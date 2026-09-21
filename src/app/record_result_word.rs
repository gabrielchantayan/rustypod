//! Record +0x14 result-word accessor — retailOS `FUN_082e2b2c` at
//! `0x082e2b2c` (**8 bytes**).
//!
//! Raw `osos.dec` words establish the complete function: `ldr r0,[r0,#0x14]`
//! at 0x082e2b2c and `bx lr` at 0x082e2b30. The next separately linked
//! function starts at 0x082e2b34 with `push {r4,r5,r6,lr}`. Full-image ARM
//! decoding finds three direct, plain unconditional `bl` call sites
//! (0x082e2938, 0x082e3530, and 0x082e4854), and zero predicated `bl` call
//! sites.
//!
//! Algorithm: return the record's 32-bit result word at +0x14 without a NULL
//! guard or other validation. The result's exact enum is unrecovered; callers
//! only test it as a status value.
//!
//! Deliberate deviations: none.

/// Record prefix ending in the observed +0x14 result word.
#[repr(C)]
pub struct RecordResultWord {
    pub words_before_result: [u32; 5],
    pub result: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(RecordResultWord, result)];

/// record_result_word — retailOS `FUN_082e2b2c` at `0x082e2b2c` (8 bytes;
/// 3 direct plain-`bl` call sites, binary-verified).
///
/// # Safety
///
/// `record` must be non-NULL and point to a readable, word-aligned
/// [`RecordResultWord`]. The retailOS load faults for invalid pointers; this
/// port deliberately retains that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_result_word")]
#[inline(never)]
pub unsafe extern "C" fn record_result_word(record: *const RecordResultWord) -> u32 {
    (*record).result
}

#[cfg(test)]
mod tests {
    use super::{record_result_word, RecordResultWord};

    #[test]
    fn returns_only_the_result_word_at_offset_14() {
        for result in [0, 1, 0x8000_0000, u32::MAX] {
            let record = RecordResultWord {
                words_before_result: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00, 0x1357_9bdf],
                result,
            };

            assert_eq!(unsafe { record_result_word(&record) }, result);
        }
    }
}
