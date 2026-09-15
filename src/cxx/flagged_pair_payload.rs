//! `flagged_pair_payload_if_set` — retailOS `FUN_081fca48` at `0x081fca48`
//! (20 bytes).
//!
//! Raw ARM establishes the true extent as five instructions at
//! `0x081fca48..0x081fca58`; the independent next function starts at
//! `0x081fca5c`. Decoding the raw image finds five direct inbound calls, all
//! unconditional plain `bl` at 0x081fcacc, 0x081fcd94, 0x081fce04,
//! 0x081fcf0c, and 0x081fd030; there are no predicated `bl` or direct-tail
//! `b` callers. The body itself contains no calls.
//!
//! # Algorithm
//!
//! Reads bit 0 of the flagged-pair byte at +0x08. If it is clear, returns
//! null; otherwise returns the address of the opaque payload at +0x04.
//! Bytes at +0x00..+0x07 are not read. Deliberate deviations: none; the
//! payload's concrete type is unrecovered, so its address remains `*mut u8`.

use super::flagged_pair_copy::FlaggedPair;

/// Returns the flagged pair's opaque payload address only when its low flag
/// bit is set.
///
/// # Safety
///
/// `record` must be readable at byte offset +0x08. It is not NULL-checked,
/// matching the original ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.flagged_pair_payload_if_set")]
#[inline(never)]
pub unsafe extern "C" fn flagged_pair_payload_if_set(record: *mut FlaggedPair) -> *mut u8 {
    if unsafe { record.cast::<u8>().add(8).read() & 1 } == 0 {
        core::ptr::null_mut()
    } else {
        unsafe { record.cast::<u8>().add(4) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_null_for_every_even_flag_value() {
        let mut words = [0x1122_3344u32, 0x5566_7788, 0xffff_fffe, 0xa5a5_5a5a];
        let record = words.as_mut_ptr().cast::<FlaggedPair>();

        assert!(unsafe { flagged_pair_payload_if_set(record) }.is_null());
        assert_eq!(words, [0x1122_3344, 0x5566_7788, 0xffff_fffe, 0xa5a5_5a5a]);
    }

    #[test]
    fn returns_word_four_for_odd_noncanonical_flag() {
        let mut words = [0x1122_3344u32, 0x5566_7788, 0xa5a5_a57f, 0xdead_beef];
        let record = unsafe { words.as_mut_ptr().add(1).cast::<FlaggedPair>() };

        let payload = unsafe { flagged_pair_payload_if_set(record) };

        assert_eq!(payload, unsafe { record.cast::<u8>().add(4) });
        assert_eq!(unsafe { payload.cast::<u32>().read() }, 0xa5a5_a57f);
        assert_eq!(words, [0x1122_3344, 0x5566_7788, 0xa5a5_a57f, 0xdead_beef]);
    }
}
