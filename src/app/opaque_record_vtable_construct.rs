//! Initializes an opaque record's virtual-dispatch word.
//!
//! `opaque_record_vtable_construct` — original: `FUN_081614e0` @
//! **0x081614e0**. Raw ARM establishes the exact **12-byte** A32 body
//! `0x081614e0..0x081614eb`: `ldr r1,[pc,#4]; str r1,[r0]; bx lr`; the word
//! at `0x081614ec` is the literal `0x08987d88`. The next real function begins
//! at `0x081614f0`. The body contains zero plain and zero predicated direct
//! BL instructions. Independent decoding finds three inbound unconditional
//! plain BL sites (`0x0821be7c`, `0x0821bf5c`, and `0x0821c034`) and zero
//! predicated inbound BL forms.
//!
//! Algorithm: replace the record's first word with the fixed retailOS
//! virtual-dispatch pointer `0x08987d88`. The literal's class identity is not
//! established, so the record remains opaque. Deliberate deviations: none.

use core::ptr;

const OPAQUE_RECORD_VTABLE: u32 = 0x0898_7d88;

/// Writes the fixed retailOS virtual-dispatch pointer into `record`.
///
/// # Safety
///
/// `record` must be non-NULL and writable for one aligned `u32`. retailOS
/// performs no validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_vtable_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_vtable_construct(record: *mut u32) {
    unsafe {
        ptr::write(record, OPAQUE_RECORD_VTABLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_the_dispatch_word() {
        let mut record = [0xdead_beef, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc];

        unsafe { opaque_record_vtable_construct(record.as_mut_ptr()) };

        assert_eq!(record, [OPAQUE_RECORD_VTABLE, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc]);
    }

    #[test]
    fn overwrites_each_possible_initial_word() {
        for initial in [0, 1, 0x8000_0000, u32::MAX] {
            let mut record = [initial];

            unsafe { opaque_record_vtable_construct(record.as_mut_ptr()) };

            assert_eq!(record[0], OPAQUE_RECORD_VTABLE);
        }
    }
}
