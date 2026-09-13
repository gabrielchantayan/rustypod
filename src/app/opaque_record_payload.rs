//! Accesses the payload immediately after an opaque record header.
//!
//! `opaque_record_payload` — original: `FUN_081614c0` @ **0x081614c0**.
//! Raw ARM establishes the exact **16-byte** extent
//! `0x081614c0..0x081614d0`: `add r0,r0,#4; str r0,[r1]; mov r0,#0; bx lr`.
//! The separately linked next function begins at `0x081614d0`.
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds **seven** direct
//! call sites, all unconditional `bl` (`0x081e33dc`, `0x081e375c`,
//! `0x08206184`, `0x082063a4`, `0x0820a1cc`, `0x0821bef4`, and `0x0821c080`);
//! there are no predicated calls or direct tail branches.
//!
//! Algorithm: write the word-aligned payload address at byte offset `+0x04`
//! through `payload_out`, then return status zero. The header and payload are
//! otherwise opaque: callers establish only that the payload begins after one
//! four-byte header word. No deliberate deviations.

use core::ptr;

/// Returns the payload start at byte offset `+0x04` from `record`.
///
/// # Safety
///
/// `record` must be non-NULL and point to an opaque record with at least one
/// header word. `payload_out` must be non-NULL and writable. Neither pointer
/// is checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_payload")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_payload(
    record: *mut u32,
    payload_out: *mut *mut u32,
) -> u32 {
    unsafe {
        ptr::write(payload_out, record.add(1));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_word_after_the_opaque_header_without_modifying_the_record() {
        let mut record = [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
        let before = record;
        let mut payload = ptr::null_mut();

        let status = unsafe { opaque_record_payload(record.as_mut_ptr(), &mut payload) };

        assert_eq!(status, 0);
        assert_eq!(payload, unsafe { record.as_mut_ptr().add(1) });
        assert_eq!(record, before);
    }

    #[test]
    fn accepts_any_word_aligned_header_value() {
        for header in [0, 1, 0x8000_0000, u32::MAX] {
            let mut record = [header, 0x2468_ace0];
            let mut payload = ptr::null_mut();

            assert_eq!(unsafe { opaque_record_payload(record.as_mut_ptr(), &mut payload) }, 0);
            assert_eq!(payload, unsafe { record.as_mut_ptr().add(1) });
            assert_eq!(record, [header, 0x2468_ace0]);
        }
    }
}
