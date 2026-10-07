//! `parse_context_construct` — `FUN_08162adc` @ **0x08162adc**, 16 bytes.
//!
//! True extent: `0x08162adc..0x08162aec`, ending before the independently
//! called destructor. Raw words are `e3a01000 e5801000 e5801004 e12fff1e`:
//! MOV r1,0; STR r1,[r0]; STR r1,[r0,4]; BX LR. Whole-image aligned A32
//! decoding finds two incoming plain BLs (0x08119dc4, 0x081b1e18), zero
//! predicated BLs, and zero internal calls.
//!
//! Initializes the eight-byte stack context used by the buffer-processing
//! wrapper at 0x08162ac0: clears both words and returns the unchanged context
//! pointer. No particular parser format or field identity is assumed.
//! Deliberate deviations: none; word indices retain four-byte spacing on hosts.

use core::ffi::c_void;

/// Initialize both parsing context words without reading their old contents.
///
/// # Safety
/// `context` must point to eight writable bytes aligned for `u32` access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_context_construct(context: *mut c_void) -> *mut c_void {
    let words = context.cast::<u32>();
    words.write(0);
    words.add(1).write(0);
    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn resets_both_words_without_touching_neighbors() {
        for initial in [[0, 0], [u32::MAX, 0], [0, u32::MAX], [0x1234_5678, 0x8765_4321]] {
            let mut storage = [0xdead_beefu32, initial[0], initial[1], 0xa5a5_a5a5];
            let context = unsafe { storage.as_mut_ptr().add(1) }.cast::<c_void>();
            assert_eq!(unsafe { parse_context_construct(context) }, context);
            assert_eq!(storage, [0xdead_beef, 0, 0, 0xa5a5_a5a5]);
        }
    }

    #[test]
    fn initializes_previously_uninitialized_storage() {
        let mut storage = MaybeUninit::<[u32; 2]>::uninit();
        let context = storage.as_mut_ptr().cast::<c_void>();
        assert_eq!(unsafe { parse_context_construct(context) }, context);
        assert_eq!(unsafe { storage.assume_init() }, [0, 0]);
    }
}
