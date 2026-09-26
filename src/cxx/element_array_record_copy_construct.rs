//! element_array_record_copy_construct — retailOS `FUN_083d7de0` @
//! **0x083d7de0** (20 bytes).
//!
//! Raw `osos.dec` words establish the exact five-instruction extent
//! `0x083d7de0..0x083d7df3`: `movs r0,r1`, `mov r1,r2`, `movne r2,#24`,
//! `bne 0x08037df8`, and `bx lr`. `push {r4,lr}` at `0x083d7df4` begins the
//! next independently linked function. Whole-image A32 branch decoding finds
//! two inbound plain `bl` calls (0x083e1b64 and 0x083e1bf4), no inbound
//! predicated `bl` calls, and no body `bl`.
//!
//! Algorithm: replace the ignored container context in `r0` with the output
//! record address. A null output returns null without reading the input;
//! otherwise tail-copy one aligned 24-byte element and return its end.
//! Deliberate deviation: the stock tail branch uses the memcpy veneer at
//! `0x08037df8`, whose target is the IRAM mirror `0x22000188`; Rust calls the
//! verified `memcpy_forward_words` body directly, preserving its grouped
//! forward-copy overlap behavior and return value.

use crate::libc::memcpy::memcpy_forward_words;

/// Copy-construct one 24-byte element-array record when output storage exists.
///
/// # Safety
///
/// When `destination` is non-null, `destination` and `source` must be valid,
/// four-byte aligned ranges of 24 bytes. Overlap retains
/// `memcpy_forward_words`' forward grouped-copy behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array_record_copy_construct(
    _container: *mut u8,
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    if destination.is_null() {
        core::ptr::null_mut()
    } else {
        memcpy_forward_words(destination, source, 24)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::element_array_record_copy_construct;

    #[test]
    fn null_destination_does_not_access_source() {
        let result = unsafe {
            element_array_record_copy_construct(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::dangling(),
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn copies_all_six_words_and_returns_the_end() {
        let source = [
            0x0102_0304u32,
            0x1122_3344,
            0x5566_7788,
            0x99aa_bbcc,
            0xddee_ff00,
            0x1357_9bdf,
        ];
        let mut destination = [0u32; 6];

        let result = unsafe {
            element_array_record_copy_construct(
                core::ptr::null_mut(),
                destination.as_mut_ptr().cast(),
                source.as_ptr().cast(),
            )
        };

        assert_eq!(destination, source);
        assert_eq!(result, unsafe { destination.as_mut_ptr().cast::<u8>().add(24) });
    }

    #[test]
    fn retains_grouped_forward_overlap_behavior() {
        let mut words = [
            0x0302_0100u32,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x1f1e_1d1c,
        ];
        let base = words.as_mut_ptr().cast::<u8>();

        unsafe {
            element_array_record_copy_construct(core::ptr::null_mut(), base.add(4), base);
        }

        assert_eq!(words, [
            0x0302_0100,
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x0f0e_0d0c,
            0x1716_1514,
            0x1f1e_1d1c,
        ]);
    }
}
