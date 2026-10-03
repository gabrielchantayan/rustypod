//! `object_mark_initialized` — `FUN_082371ac` at load address `0x082371ac`.
//! True extent: **52 bytes**, `0x082371ac..0x082371e0`; the next entry begins
//! with `push {r2,r3,r4,r5,r6,r7,r8,r9,r10,lr}`. Raw aligned A32 decoding
//! verifies two inbound BLs: one plain at `0x08237338`, one predicated
//! (`bleq`) at `0x08237258`. One outbound plain BL at `0x082371c4` targets
//! `0x08153d70`; there are no predicated outbound BLs.
//!
//! Read the object's initialization byte at `+0x70`. If zero, call the
//! retail helper, set the byte to one on its zero result, and return zero;
//! a nonzero helper result would instead return one without storing. The
//! helper's complete eight-byte body is `e3a00000 e12fff1e` (`mov r0,#0;
//! bx lr`), so that failure path is unreachable in this firmware. Both
//! callers ignore the return; the constructor at `0x0823731c` first clears
//! the byte and the caller at `0x082371e0` gates the call on the same byte.
//!
//! Deliberate deviation: fold the verified constant-zero helper into this
//! port, eliminating its call and unreachable failure path, without adding
//! a guessed callee identity or seam. No observable behavioral deviations.

const INITIALIZED_OFFSET: usize = 0x70;

/// Mark an opaque object initialized, preserving any existing nonzero byte.
///
/// # Safety
/// `object` must be readable through byte `+0x70`, and that byte must be
/// writable when zero. No pointer validation is performed by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_mark_initialized(object: *mut u8) -> u32 {
    let initialized = object.add(INITIALIZED_OFFSET);
    if initialized.read() == 0 {
        initialized.write(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_flag_values_match_retail_and_preserve_other_bytes() {
        for flag in 0..=u8::MAX {
            let mut object = [0xa5; INITIALIZED_OFFSET + 9];
            object[INITIALIZED_OFFSET] = flag;
            let mut expected = object;
            // Reference: the decoded helper returns zero, so only a zero
            // input byte takes the conditional STRBEQ.
            if flag == 0 {
                expected[INITIALIZED_OFFSET] = 1;
            }
            let result = unsafe { object_mark_initialized(object.as_mut_ptr()) };
            assert_eq!(result, 0, "flag={flag:#04x}");
            assert_eq!(object, expected, "flag={flag:#04x}");
        }
    }

    #[test]
    fn repeated_initialization_preserves_the_initialized_state() {
        let mut object = [0x5a; INITIALIZED_OFFSET + 1];
        object[INITIALIZED_OFFSET] = 0;
        for _ in 0..3 {
            assert_eq!(unsafe { object_mark_initialized(object.as_mut_ptr()) }, 0);
            assert_eq!(object[INITIALIZED_OFFSET], 1);
            assert_eq!(&object[..INITIALIZED_OFFSET], &[0x5a; INITIALIZED_OFFSET]);
        }
    }
}
