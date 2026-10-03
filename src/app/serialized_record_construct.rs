//! Constructor prefix for a serialized record owned by a decoding context.
//!
//! Original: `FUN_082693ac` @ `0x082693ac`. True extent: 20 bytes,
//! comprising 16 instruction bytes and the literal at `0x082693bc`; the next
//! independent function starts at `0x082693c0` with a NULL-check/delete tail.
//! Whole-image aligned A32 decoding finds two inbound plain BLs at
//! `0x08268af4` and `0x08268b3c`, zero predicated BLs, and no outbound calls.
//!
//! Stores the target-width context word at +4, installs the literal vtable
//! address at +0, and returns the original storage pointer unchanged. The
//! caller allocates 0x1c bytes for record kinds 1 and 3; kind 1 replaces the
//! vtable afterward. Remaining record fields are deliberately untouched.
//! The concrete class identity is not established. Deliberate deviations:
//! none; pointer fields remain u32 words on hosts as on ARM.

/// # Safety
/// `storage` must be four-byte aligned and writable for at least two words.
/// `context` is an opaque target address; this constructor does not dereference it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn serialized_record_construct(storage: *mut u32, context: u32) -> *mut u32 {
    storage.add(1).write(context);
    storage.write(0x089a_8140);
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_only_prefix_and_preserves_return_identity() {
        for context in [0, 1, 0x0800_0000, 0xffff_ffff] {
            let mut words = [0xa5a5_5a5a; 9];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let returned = unsafe { serialized_record_construct(storage, context) };
            assert_eq!(returned, storage);
            assert_eq!(words, [0xa5a5_5a5a, 0x089a_8140, context,
                0xa5a5_5a5a, 0xa5a5_5a5a, 0xa5a5_5a5a, 0xa5a5_5a5a,
                0xa5a5_5a5a, 0xa5a5_5a5a]);
        }
    }

    #[test]
    fn reconstructing_replaces_context_without_clearing_payload() {
        let mut words = [0, 0, 7, 8, 9, 10, 11];
        unsafe { serialized_record_construct(words.as_mut_ptr(), 0x0800_1234); }
        words[0] = 0x1234_5678;
        unsafe { serialized_record_construct(words.as_mut_ptr(), 0); }
        assert_eq!(words, [0x089a_8140, 0, 7, 8, 9, 10, 11]);
    }
}
