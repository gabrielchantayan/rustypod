//! `flagged_pair_clear` — retailOS `FUN_081fca5c` at `0x081fca5c` (16 bytes).
//!
//! Raw ARM establishes the true extent as `0x081fca5c..0x081fca6b`: zero r1;
//! store it to +0x00; store it as a byte to +0x08; return with r0 unchanged.
//! The independent next function starts at `0x081fca6c`. Decoding the raw
//! inbound branch words finds four direct inbound calls, all unconditional
//! plain `bl` at 0x081b7790, 0x081b7ad4, 0x08214d68, and 0x08214e00; there
//! are no predicated `bl` or direct-tail `b` callers. The body itself has no
//! calls.
//!
//! # Algorithm
//!
//! Clears the opaque first word and flag byte of a flagged pair, preserving its
//! second word and trailing bytes, then returns the original pointer.
//! Deliberate deviations: volatile stores preserve the retail store order and
//! prevent LLVM from combining the stores; the concrete C++ type remains
//! unrecovered, so the observed shared [`FlaggedPair`] layout is used.

use super::flagged_pair_copy::FlaggedPair;

/// Clears `record.first` and `record.flag`, returning `record`.
///
/// # Safety
///
/// `record` must be four-byte aligned and writable through byte offset +0x08.
/// It is not NULL-checked, matching the original ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.flagged_pair_clear")]
#[inline(never)]
pub unsafe extern "C" fn flagged_pair_clear(record: *mut FlaggedPair) -> *mut FlaggedPair {
    unsafe {
        core::ptr::addr_of_mut!((*record).first).write_volatile(0);
        core::ptr::addr_of_mut!((*record).flag).write_volatile(0);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::{flagged_pair_clear, FlaggedPair};

    #[test]
    fn clears_only_observed_fields_and_returns_input() {
        let mut record = FlaggedPair {
            first: 0x1357_9bdf,
            second: 0x2468_ace0,
            flag: 0xff,
            reserved: [0xa1, 0xb2, 0xc3],
        };

        let returned = unsafe { flagged_pair_clear(&mut record) };

        assert!(core::ptr::eq(returned, &mut record));
        assert_eq!(record.first, 0);
        assert_eq!(record.second, 0x2468_ace0);
        assert_eq!(record.flag, 0);
        assert_eq!(record.reserved, [0xa1, 0xb2, 0xc3]);
    }

    #[test]
    fn clears_noncanonical_flag_without_touching_adjacent_bytes() {
        let mut words = [0x1122_3344u32, 0x5566_7788, 0xdead_be7f, 0xa5a5_5a5a];
        let record = words.as_mut_ptr().cast::<FlaggedPair>();

        let returned = unsafe { flagged_pair_clear(record) };

        assert_eq!(returned, record);
        assert_eq!(words, [0, 0x5566_7788, 0xdead_be00, 0xa5a5_5a5a]);
    }
}
