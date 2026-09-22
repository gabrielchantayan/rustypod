//! Record preferred string accessor — original: `FUN_08271380` @ `0x08271380`.
//!
//! Raw ARM establishes the true 20-byte extent: `ldr r1,[r0,#0x28]` at
//! `0x08271380` through `bx lr` at `0x08271390`; the next independent
//! function starts at `0x08271394`. Full-image A32 decoding finds three
//! inbound plain `bl` call sites (`0x08108d00`, `0x08109b24`, and
//! `0x0810a118`), zero predicated inbound `bl` call sites, and no calls in
//! this function.
//!
//! Returns the record's optional string word at `+0x28` when nonzero;
//! otherwise returns its default string word at `+0x08`.
//!
//! Deliberate deviation: the target's 32-bit string addresses remain `u32`
//! on host too, so record fields are indexed as target words rather than
//! represented with host-width pointers.

const DEFAULT_STRING_WORD: usize = 0x08 / 4;
const PREFERRED_STRING_WORD: usize = 0x28 / 4;

/// Returns the preferred string address, falling back to the default address.
///
/// # Safety
/// `record` must point to readable target words at `+0x08` and `+0x28`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_preferred_string(record: *const u32) -> u32 {
    let preferred = *record.add(PREFERRED_STRING_WORD);
    if preferred != 0 {
        preferred
    } else {
        *record.add(DEFAULT_STRING_WORD)
    }
}

#[cfg(test)]
mod tests {
    use super::record_preferred_string;

    unsafe fn reference(record: *const u32) -> u32 {
        let preferred = *record.add(10);
        if preferred == 0 { *record.add(2) } else { preferred }
    }

    #[test]
    fn returns_preferred_string_when_present() {
        let record = [0, 0, 0x0801_2345, 0, 0, 0, 0, 0, 0, 0, 0x0820_abcd];
        assert_eq!(unsafe { record_preferred_string(record.as_ptr()) }, unsafe {
            reference(record.as_ptr())
        });
    }

    #[test]
    fn falls_back_when_preferred_string_is_null() {
        let record = [0, 0, 0x0801_2345, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(unsafe { record_preferred_string(record.as_ptr()) }, unsafe {
            reference(record.as_ptr())
        });
    }
}
