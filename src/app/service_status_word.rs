//! `service_status_word` — original: `FUN_081d0df8` @ `0x081d0df8` (8 bytes,
//! `0x081d0df8..0x081d0e00`; the next real function starts at `0x081d0e00`).
//! Whole-image ARM B/BL-immediate decoding finds three inbound plain,
//! unconditional `bl` calls (0x08125ea4, 0x0819ab78, and 0x082246e0), with
//! zero predicated direct `bl` calls.
//!
//! # Algorithm
//!
//! Return the 32-bit status word at byte offset `+0x08` in the supplied
//! service subobject. The callers use the result as a zero/nonzero status;
//! the `ldr` itself imposes no interpretation, validation, or mutation.
//!
//! # Deliberate deviations
//!
//! None.

const STATUS_WORD_OFFSET: usize = 8;

/// Returns the service subobject's status word.
///
/// # Safety
///
/// `service` must be non-NULL, four-byte aligned, and readable through
/// `service + 0x0b`. RetailOS performs no validation before its word load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.service_status_word")]
pub unsafe extern "C" fn service_status_word(service: *const u8) -> u32 {
    service.add(STATUS_WORD_OFFSET).cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ServicePrefix {
        preceding_words: [u32; 2],
        status: u32,
        following_word: u32,
    }

    #[test]
    fn returns_each_status_word_without_mutating_neighbors() {
        let mut service = ServicePrefix {
            preceding_words: [0xa5a5_a5a5, 0x5a5a_5a5a],
            status: 0,
            following_word: 0xfeed_face,
        };

        for expected in [0, 1, 0x8000_0000, u32::MAX] {
            service.status = expected;
            let before = service;

            let actual = unsafe { service_status_word((&service as *const ServicePrefix).cast()) };

            assert_eq!(actual, expected);
            assert_eq!(service.preceding_words, before.preceding_words);
            assert_eq!(service.following_word, before.following_word);
        }
    }
}
