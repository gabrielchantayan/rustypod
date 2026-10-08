//! `text_buffer_context_destroy` — `FUN_08123ce8` @ **0x08123ce8**, 4 bytes.
//!
//! Raw word `0xe12fff1e` is `bx lr`, not a veneer. The preceding body
//! returns at 0x08123ce0 followed by its literal at 0x08123ce4; the next
//! independent function begins at 0x08123cec (`mov r0, #1; bx lr`).
//! Whole-image aligned ARM BL decoding finds two plain inbound calls at
//! 0x080b56e0 and 0x080b5954, zero predicated calls, and zero internal calls.
//! No aligned DATA words contain the entry address (or its Thumb-tagged form).
//!
//! Both callers pass the stack context at sp+0x160, then overwrite r0.
//! Nearby operations append text and clear its backing buffer through
//! 0x08123c20. Algorithm: return the object word unchanged without reading,
//! writing, or releasing anything. Preserve r0 despite Ghidra's void signature.
//! Deliberate deviations: none. A distinct target text section retains this
//! BL target independently of other identical empty destructors.

use core::ffi::c_void;

/// Finish a text-buffer context without accessing the object or its buffer.
/// NULL, unaligned, and dangling object words are accepted unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.text_buffer_context_destroy")]
#[inline(never)]
pub unsafe extern "C" fn text_buffer_context_destroy(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_object_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let object = word as *mut c_void;
            assert_eq!(unsafe { text_buffer_context_destroy(object) }, object);
        }
    }

    #[test]
    fn leaves_context_and_canaries_unchanged() {
        let mut storage = [0xa5u8; 40];
        for (index, byte) in storage[4..36].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(4) }.cast::<c_void>();
        assert_eq!(unsafe { text_buffer_context_destroy(object) }, object);
        assert_eq!(storage, before);
    }
}
