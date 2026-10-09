//! Release a non-NULL buffer marked by the 0xffff ownership sentinel.

/// Opaque owner prefix; only the buffer and sentinel semantics are established.
/// Native host pointers widen the final fields; target offsets remain +20/+24.
#[repr(C)]
pub struct SentinelBufferOwner {
    pub prefix: [u32; 5],
    pub buffer: *mut u8,
    pub sentinel: u16,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(SentinelBufferOwner, buffer) == 0x14);
    assert!(core::mem::offset_of!(SentinelBufferOwner, sentinel) == 0x18);
};

/// sentinel_buffer_release — FUN_080f6af8 @ 0x080f6af8, true size 68 bytes.
/// Raw ARM ends at pop {r4,pc} @ 0x080f6b38; the independent accessor at
/// 0x080f6b3c begins the next function. Whole-image decoding verifies two
/// incoming plain BLs (0x080f6a64, 0x080f7428), zero predicated incoming BLs,
/// one outgoing plain BL (0x080f6b24 to operator_delete @ 0x082aad24), and
/// zero predicated outgoing BLs. Ghidra's 48-byte extent wrongly treats
/// operator_delete as noreturn and omits the field clearing and success return.
///
/// Return zero unchanged if buffer is NULL or sentinel is not 0xffff.
/// Otherwise tag-2 delete the saved buffer, clear buffer and sentinel after
/// deletion, and return one. Callers prepare/release the enclosing object's
/// buffers; the enclosing class and sentinel's wider domain are unidentified.
/// Deliberate deviations: existing operator_delete uses the heap ops dispatch;
/// native host pointers widen the struct fields. No target behavior deviation.
///
/// # Safety
/// `owner` must be a live, aligned, writable owner. A non-NULL buffer marked
/// 0xffff must be accepted by operator_delete; its deletion must not destroy
/// the owner itself.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sentinel_buffer_release(owner: *mut SentinelBufferOwner) -> u32 {
    let buffer = (*owner).buffer;
    if buffer.is_null() || (*owner).sentinel != u16::MAX {
        return 0;
    }
    crate::heap::veneers::operator_delete(buffer);
    (*owner).buffer = core::ptr::null_mut();
    (*owner).sentinel = 0;
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[test]
    fn null_buffer_preserves_even_the_release_sentinel() {
        let _heap = mock_heap();
        for sentinel in [0, 1, 0xfffe, 0xffff] {
            let mut owner = SentinelBufferOwner {
                prefix: [0xa5a5a5a5; 5], buffer: core::ptr::null_mut(), sentinel,
            };
            assert_eq!(unsafe { sentinel_buffer_release(&mut owner) }, 0);
            assert!(owner.buffer.is_null());
            assert_eq!(owner.sentinel, sentinel);
            assert_eq!(owner.prefix, [0xa5a5a5a5; 5]);
            assert_eq!(free_log().0, 0);
        }
    }

    #[test]
    fn only_exact_sentinel_releases_and_second_call_is_inert() {
        let _heap = mock_heap();
        let mut payload = [0u8; 8];
        let buffer = payload.as_mut_ptr();
        for sentinel in 0..u16::MAX {
            let mut owner = SentinelBufferOwner {
                prefix: [0x12345678; 5], buffer, sentinel,
            };
            assert_eq!(unsafe { sentinel_buffer_release(&mut owner) }, 0);
            assert_eq!(owner.buffer, buffer);
            assert_eq!(owner.sentinel, sentinel);
            assert_eq!(owner.prefix, [0x12345678; 5]);
        }
        assert_eq!(free_log().0, 0);
        let mut owner = SentinelBufferOwner {
            prefix: [0x12345678; 5], buffer, sentinel: u16::MAX,
        };
        assert_eq!(unsafe { sentinel_buffer_release(&mut owner) }, 1);
        assert_eq!(free_log(), (1, buffer, 2));
        assert!(owner.buffer.is_null());
        assert_eq!(owner.sentinel, 0);
        assert_eq!(owner.prefix, [0x12345678; 5]);
        assert_eq!(unsafe { sentinel_buffer_release(&mut owner) }, 0);
        assert_eq!(free_log(), (1, buffer, 2));
    }
}
