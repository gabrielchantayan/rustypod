//! MPEG audio header compatibility — `FUN_08281d48` @ `0x08281d48`.
//!
//! True extent: 32 bytes (`0x08281d48..0x08281d68`); the literal mask at
//! `0x08281d68` is followed by the next separately entered function at
//! `0x08281d6c`. Full-image A32 decoding finds three inbound plain `bl` call
//! sites (`0x08281624`, `0x08281f10`, and `0x082826e8`), zero predicated inbound
//! `bl` call sites, and no outgoing `bl` calls.
//!
//! # Algorithm
//!
//! Compares the MPEG audio header's synchronization, version, and sample-rate
//! bits against the saved header at context offset `+0x38`. Equal masked bits
//! return zero; a mismatch returns status 3. Deliberate deviations: none.

const HEADER_OFFSET: usize = 0x38;
const COMPATIBILITY_MASK: u32 = 0xfffe_0c00;
const STATUS_MISMATCH: u32 = 3;

/// Returns zero when `header` is compatible with the saved MPEG audio header.
///
/// # Safety
///
/// `context` must be valid to read an aligned `u32` at byte offset `+0x38`.
/// This is the original's unguarded load contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mpeg_audio_header_matches_context(context: *const u8, header: u32) -> u32 {
    let saved_header = (context.add(HEADER_OFFSET) as *const u32).read();
    if header & COMPATIBILITY_MASK == saved_header & COMPATIBILITY_MASK {
        0
    } else {
        STATUS_MISMATCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_unmasked_header_fields() {
        let mut context = [0u32; 15];
        context[HEADER_OFFSET / 4] = 0xfffb_9400;

        assert_eq!(
            unsafe { mpeg_audio_header_matches_context(context.as_ptr().cast(), 0xfffb_97ff) },
            0
        );
    }

    #[test]
    fn rejects_different_sample_rate_bits() {
        let mut context = [0u32; 15];
        context[HEADER_OFFSET / 4] = 0xfffb_9400;

        assert_eq!(
            unsafe { mpeg_audio_header_matches_context(context.as_ptr().cast(), 0xfffb_9800) },
            STATUS_MISMATCH
        );
    }

    #[test]
    fn rejects_different_sync_or_version_bits() {
        let mut context = [0u32; 15];
        context[HEADER_OFFSET / 4] = 0xfffb_9400;

        assert_eq!(
            unsafe { mpeg_audio_header_matches_context(context.as_ptr().cast(), 0xfff9_9400) },
            STATUS_MISMATCH
        );
    }
}
