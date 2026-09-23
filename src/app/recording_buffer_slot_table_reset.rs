//! Reset the recording buffer's fixed slot table.
//!
//! Port: [`recording_buffer_slot_table_reset`] — original: `FUN_08167ef0` @
//! `0x08167ef0` (**56 bytes; zero direct `bl` calls and one predicated `blt`
//! loop branch**). Raw ARM reaches `bx lr` at `0x08167f24`; the next function
//! starts at `0x08167f28`.
//!
//! ## Algorithm
//!
//! If `keep_pending_marker` is zero, clear the word at `buffer + 0x338`. Always
//! clear the three adjacent bookkeeping words at `+0x330`, `+0x334`, and
//! `+0x33c`, then clear the word at `+0x38` in each of 64 twelve-byte slots.
//!
//! ## Deliberate deviations
//!
//! The retail routine uses a conditional branch-with-link solely as its loop
//! back edge. Rust uses a range loop; the observable volatile word stores and
//! their order are retained.

const SLOT_COUNT: usize = 0x40;
const SLOT_STRIDE: usize = 0xc;
const SLOT_WORD_OFFSET: usize = 0x38;
const FIRST_BOOKKEEPING_OFFSET: usize = 0x330;
const PENDING_MARKER_OFFSET: usize = 0x338;
const LAST_BOOKKEEPING_OFFSET: usize = 0x33c;

/// recording_buffer_slot_table_reset — original: `FUN_08167ef0` @ `0x08167ef0`.
///
/// `buffer` must be a non-NULL, four-byte-aligned recording buffer with at
/// least `0x340` writable bytes. `keep_pending_marker != 0` preserves `+0x338`;
/// retailOS performs no validation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.recording_buffer_slot_table_reset")]
pub unsafe extern "C" fn recording_buffer_slot_table_reset(buffer: *mut u8, keep_pending_marker: u32) {
    if keep_pending_marker == 0 {
        core::ptr::write_volatile(buffer.add(PENDING_MARKER_OFFSET).cast::<u32>(), 0);
    }
    core::ptr::write_volatile(buffer.add(FIRST_BOOKKEEPING_OFFSET).cast::<u32>(), 0);
    core::ptr::write_volatile(buffer.add(FIRST_BOOKKEEPING_OFFSET + 4).cast::<u32>(), 0);
    core::ptr::write_volatile(buffer.add(LAST_BOOKKEEPING_OFFSET).cast::<u32>(), 0);

    for slot in 0..SLOT_COUNT {
        core::ptr::write_volatile(buffer.add(SLOT_WORD_OFFSET + slot * SLOT_STRIDE).cast::<u32>(), 0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(4))]
    struct Buffer([u8; 0x340]);

    fn word(buffer: &Buffer, offset: usize) -> u32 {
        unsafe { core::ptr::read_unaligned(buffer.0.as_ptr().add(offset).cast::<u32>()) }
    }

    #[test]
    fn clears_bookkeeping_and_every_slot_when_marker_is_not_kept() {
        let mut buffer = Buffer([0xa5; 0x340]);
        unsafe { recording_buffer_slot_table_reset(buffer.0.as_mut_ptr(), 0) };

        for offset in [FIRST_BOOKKEEPING_OFFSET, FIRST_BOOKKEEPING_OFFSET + 4, PENDING_MARKER_OFFSET, LAST_BOOKKEEPING_OFFSET] {
            assert_eq!(word(&buffer, offset), 0);
        }
        for slot in 0..SLOT_COUNT {
            assert_eq!(word(&buffer, SLOT_WORD_OFFSET + slot * SLOT_STRIDE), 0);
        }
        assert_eq!(word(&buffer, SLOT_WORD_OFFSET + 4), 0xa5a5_a5a5);
    }

    #[test]
    fn retains_pending_marker_for_nonzero_keep_argument() {
        let mut buffer = Buffer([0xa5; 0x340]);
        unsafe { recording_buffer_slot_table_reset(buffer.0.as_mut_ptr(), 7) };

        assert_eq!(word(&buffer, PENDING_MARKER_OFFSET), 0xa5a5_a5a5);
        assert_eq!(word(&buffer, FIRST_BOOKKEEPING_OFFSET), 0);
        assert_eq!(word(&buffer, LAST_BOOKKEEPING_OFFSET), 0);
        for slot in 0..SLOT_COUNT {
            assert_eq!(word(&buffer, SLOT_WORD_OFFSET + slot * SLOT_STRIDE), 0);
        }
    }
}
