//! Tagged stream-handle validation — `FUN_08087974` @ `0x08087974`.
//!
//! Original size: 36 bytes of code, with a separate 4-byte literal-pool word
//! at `0x08087998`. Raw ARM confirms the code extends from `cmp r0,#0` at
//! `0x08087974` through `bx lr` at `0x08087994`; the next distinct function
//! starts at `0x0808799c`. It accepts a non-NULL handle only when its first
//! word is the `"mrts"` tag (`0x7374_726d`) and returns 0; it returns -50 for
//! a NULL or foreign-tagged handle without modifying it. Decoding every ARM
//! B/BL-immediate word in `osos.dec` found six verified inbound calls, all
//! unconditional `bl` at `0x0805b6e0`, `0x0805b720`, `0x0805b748`,
//! `0x0805b7dc`, `0x0805b814`, and `0x0805b844`; there are no predicated
//! calls, direct B tail callers, or aligned data-word references. Deliberate
//! deviations: none.

/// Required first word of a stream handle. Its in-memory little-endian bytes
/// are `"mrts"`.
pub const MRTS_TAG: u32 = 0x7374_726d;

/// stream_handle_validate — original: `FUN_08087974` @ `0x08087974` (36
/// bytes).
///
/// Returns zero when `handle` is non-NULL and starts with [`MRTS_TAG`], else
/// returns the retailOS invalid-handle error -50. The handle is not modified.
///
/// # Safety
///
/// A non-NULL `handle` must be valid and aligned for a `u32` read, matching
/// the original ARM `ldr`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_handle_validate")]
#[inline(never)]
pub unsafe extern "C" fn stream_handle_validate(handle: *const u32) -> i32 {
    if handle.is_null() {
        return -50;
    }

    if unsafe { handle.read() } == MRTS_TAG {
        0
    } else {
        -50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_handle_is_invalid() {
        assert_eq!(unsafe { stream_handle_validate(core::ptr::null()) }, -50);
    }

    #[test]
    fn matching_tag_is_valid_without_mutation() {
        let handle = [MRTS_TAG, 0xfeed_beef];

        assert_eq!(unsafe { stream_handle_validate(handle.as_ptr()) }, 0);
        assert_eq!(handle, [MRTS_TAG, 0xfeed_beef]);
    }

    #[test]
    fn nonmatching_first_word_is_invalid() {
        for tag in [0, 0x7374_726c, 0x7374_726e, u32::MAX] {
            let handle = [tag, MRTS_TAG];
            assert_eq!(unsafe { stream_handle_validate(handle.as_ptr()) }, -50, "tag {tag:#010x}");
        }
    }

    #[test]
    fn validation_reads_only_the_tag_word() {
        let handle = [MRTS_TAG, 0];
        assert_eq!(unsafe { stream_handle_validate(handle.as_ptr()) }, 0);
    }
}
