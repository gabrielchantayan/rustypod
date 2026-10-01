//! Flag-gated UI value comparison — `FUN_0829dd5c` @ `0x0829dd5c`.
//!
//! Raw ARM extent: 36 bytes, `0x0829dd5c..0x0829dd80`; the preceding
//! function returns at `0x0829dd58`, and the next literal-return function
//! starts at `0x0829dd80`. Whole-image aligned ARM decoding verifies two
//! plain incoming BLs (`0x08141128`, `0x0814116c`), zero predicated incoming
//! BLs, and zero outgoing BLs of either kind.
//!
//! Read the byte at +0xec first. If nonzero, compare the aligned 32-bit
//! value at +0xe8 with the requested value; return exactly 1 on equality,
//! otherwise 0. The caller uses this result to select drawing attributes.
//! The value's domain is deliberately left unnamed: no calendar/date ABI
//! is assumed from the surrounding drawing loop.
//!
//! Deliberate deviations: none. No null guard, no pointer-sized fields,
//! and no callee seams. The disabled path does not read the value word.

const VALUE_OFFSET: usize = 0xe8;
const ENABLED_OFFSET: usize = 0xec;

/// Return whether the UI object's enabled value equals `requested_value`.
///
/// # Safety
/// `object + 0xec` must be readable. When that byte is nonzero,
/// `object + 0xe8` must also be a readable, four-byte-aligned `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_flagged_value_matches(object: *const u8, requested_value: u32) -> u32 {
    if object.add(ENABLED_OFFSET).read() == 0 {
        return 0;
    }
    (object.add(VALUE_OFFSET).cast::<u32>().read() == requested_value) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Object { bytes: [u8; 0xf0] }

    #[test]
    fn flag_and_full_word_equality() {
        let values: [u32; 6] = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1234_5678];
        let mut object = Object { bytes: [0xa5; 0xf0] };
        for enabled in 0..=u8::MAX {
            object.bytes[ENABLED_OFFSET] = enabled;
            for stored in values {
                object.bytes[VALUE_OFFSET..VALUE_OFFSET + 4].copy_from_slice(&stored.to_ne_bytes());
                let before = object.bytes;
                for requested in values {
                    let expected = u32::from(enabled != 0 && stored == requested);
                    assert_eq!(unsafe { ui_flagged_value_matches(object.bytes.as_ptr(), requested) }, expected);
                }
                assert_eq!(object.bytes, before);
            }
        }
    }

    #[test]
    fn disabled_path_does_not_require_an_initialized_value() {
        // Only the flag is initialized. Reading the uninitialized value
        // would be invalid even though its storage is in bounds.
        let mut object = core::mem::MaybeUninit::<Object>::uninit();
        unsafe {
            let bytes = object.as_mut_ptr().cast::<u8>();
            bytes.add(ENABLED_OFFSET).write(0);
            assert_eq!(ui_flagged_value_matches(bytes, 0xffff_ffff), 0);
        }
    }
}
