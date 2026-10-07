//! `chunk_probe_context_destroy` — `FUN_0814cd44` @ **0x0814cd44**, 4 bytes.
//!
//! Raw A32 word `0xe12fff1e` is `bx lr`. The next real body starts at
//! 0x0814cd48: load the member at +4, load its vtable and slot +0x14,
//! then tail-dispatch through r1. It is not part of this destructor.
//! Whole-image aligned raw decoding finds two incoming plain BLs at
//! 0x0820c7a4 and 0x0820c7ac, zero predicated BLs, zero outgoing calls,
//! and no aligned DATA references to this entry.
//!
//! Caller 0x0820c668 constructs a four-byte temporary at sp+0x10 using
//! 0x0814cd40, probes chunk headers with 0x0814cbb4, and destroys the
//! temporary on both result paths. The probe ignores its first argument;
//! neither destructor call consumes r0. No class identity is inferred.
//! Algorithm: return immediately without reading or writing memory, preserving
//! the incoming object word in r0. Deliberate deviations: none. Naked target
//! assembly retains the original register-transparent one-instruction body.

/// Destroy the chunk-probe temporary; NULL and invalid object words are accepted.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn chunk_probe_context_destroy(_context: *mut u8) -> *mut u8 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn chunk_probe_context_destroy(context: *mut u8) -> *mut u8 {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_invalid_object_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, u32::MAX as usize, usize::MAX] {
            let context = word as *mut u8;
            assert_eq!(unsafe { chunk_probe_context_destroy(context) }, context);
        }
    }

    #[test]
    fn leaves_temporary_and_adjacent_canaries_unchanged() {
        let mut storage = [0xa5u8, 0x5a, 0x12, 0x34, 0x56, 0x78, 0x3c, 0xc3];
        let before = storage;
        let context = unsafe { storage.as_mut_ptr().add(2) };
        assert_eq!(unsafe { chunk_probe_context_destroy(context) }, context);
        assert_eq!(storage, before);
    }
}
