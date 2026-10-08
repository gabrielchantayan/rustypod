//! `byte_buffer_destroy` — original `FUN_08144000` @ 0x08144000.
//!
//! True extent: 32 bytes, 0x08144000..0x08144020. The next function
//! starts with `ldr r1,[r0,#24]`. Raw A32 branch decoding verifies two
//! incoming plain BLs (0x08184d54, 0x081850ac), no predicated incoming
//! BLs, and one outgoing BLNE to `free_wrapper` @ 0x080e7970 (no plain
//! outgoing BLs). No aligned image word references this entry as data.
//! Load the buffer's data pointer, free it with heap tag 24 if non-NULL,
//! and return the buffer unchanged. Do not clear the dangling pointer,
//! length, or capacity and do not free the buffer object itself. The
//! constructor @ 0x08143fc0 initializes these three words; append @
//! 0x08143f38 uses word +4 as the current length. Both callers destroy
//! the buffer before passing the returned object to operator_delete.
//!
//! Deliberate deviations: a Rust conditional call replaces ARM BLNE;
//! the existing free_wrapper uses the project's heap ops dispatch. The
//! data pointer widens on hosts; repr(C) retains the exact three-word
//! target layout. No new callee seam.
//! Verification: all 14720 host tests and the ARM release build pass.
//! match.py reports 8 original versus 12 Rust instructions (exit 1):
//! LLVM returns early on NULL, adds a frame pointer, and emits an ordinary
//! guarded BL. The pointer load, tag 24, free, and object return remain.

use crate::heap::veneers::free_wrapper;

#[repr(C)]
pub struct ByteBuffer {
    pub data: *mut u8,
    pub length: u32,
    pub capacity: u32,
}

/// # Safety
/// `buffer` must point to an aligned, readable ByteBuffer, with data NULL
/// or a live tag-24 allocation. The data pointer remains dangling after
/// release; the caller must not destroy a nonempty buffer twice.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn byte_buffer_destroy(buffer: *mut ByteBuffer) -> *mut ByteBuffer {
    let data = (*buffer).data;
    if !data.is_null() {
        free_wrapper(data, 24);
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[repr(C)]
    struct Fixture {
        before: [u32; 2],
        buffer: ByteBuffer,
        after: [u32; 2],
    }

    #[test]
    fn null_data_ignores_nonzero_length_and_capacity() {
        let _heap = mock_heap();
        let mut fixture = Fixture {
            before: [0x12345678, 0x87654321],
            buffer: ByteBuffer { data: core::ptr::null_mut(), length: u32::MAX, capacity: 17 },
            after: [0xabcdef01, 0x10203040],
        };
        let buffer = &mut fixture.buffer as *mut ByteBuffer;
        assert_eq!(unsafe { byte_buffer_destroy(buffer) }, buffer);
        assert_eq!(free_log().0, 0);
        assert!(fixture.buffer.data.is_null());
        assert_eq!(fixture.buffer.length, u32::MAX);
        assert_eq!(fixture.buffer.capacity, 17);
        assert_eq!(fixture.before, [0x12345678, 0x87654321]);
        assert_eq!(fixture.after, [0xabcdef01, 0x10203040]);
    }

    #[test]
    fn live_data_is_released_even_with_zero_length_and_capacity() {
        let _heap = mock_heap();
        let mut payload = [0x5au8; 32];
        let data = payload.as_mut_ptr();
        let mut fixture = Fixture {
            before: [0x12345678, 0x87654321],
            buffer: ByteBuffer { data, length: 0, capacity: 0 },
            after: [0xabcdef01, 0x10203040],
        };
        let buffer = &mut fixture.buffer as *mut ByteBuffer;
        assert_eq!(unsafe { byte_buffer_destroy(buffer) }, buffer);
        assert_eq!(free_log(), (1, data, 24));
        assert_eq!(fixture.buffer.data, data);
        assert_eq!(fixture.buffer.length, 0);
        assert_eq!(fixture.buffer.capacity, 0);
        assert_eq!(fixture.before, [0x12345678, 0x87654321]);
        assert_eq!(fixture.after, [0xabcdef01, 0x10203040]);
    }
}
