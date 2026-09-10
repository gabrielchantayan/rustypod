//! `string_object_owner_destroy` — original: `FUN_0804bd88` @ load address
//! `0x0804bd88` (40 bytes, not Ghidra's 32-byte extent). Raw ARM has ten
//! instructions through `pop {r4, pc}` at 0x0804bdac; the distinct next
//! function starts at 0x0804bdb0.
//!
//! ```text
//! 0804bd88  cmp   r0, #0
//! 0804bd8c  mvneq r0, #0x31       @ -50
//! 0804bd90  push  {r4, lr}
//! 0804bd94  popeq {r4, pc}
//! 0804bd98  add   r0, r0, #4
//! 0804bd9c  bl    0x082792fc      @ string_object_destroy_veneer
//! 0804bda0  sub   r0, r0, #4
//! 0804bda4  bl    0x082aad24      @ operator_delete
//! 0804bda8  mov   r0, #0
//! 0804bdac  pop   {r4, pc}
//! ```
//!
//! Full-image decoding of every ARM `B`/`BL` immediate finds 12 inbound
//! calls, all unconditional `bl` (at 0x0806da90, 0x0806dad4, 0x0806dbfc,
//! 0x0806dc10, 0x0806dd04, 0x0806dda0, 0x080718b4, 0x080718c4,
//! 0x080718d0, 0x080718dc, 0x080718e8, and 0x080718f4); there are no
//! predicated forms, direct `B` callers, or data words holding the entry.
//!
//! The owner object's first word is opaque, followed by an embedded
//! [`StringObject`] at target word index 1. NULL returns status -50 without
//! touching either callee. Otherwise it destroys that member, converts the
//! returned member pointer back to its enclosing owner by subtracting one ARM
//! word, frees the owner with tag-2 `operator_delete`, and returns zero.
//! Deliberate deviations: none. The host fixture aligns the embedded object
//! for its native pointer width while retaining the target's four-byte word
//! relation; the implementation itself uses word indices rather than host
//! byte-layout assumptions.

use crate::cxx::string_object::{string_object_destroy_veneer, StringObject};
use crate::heap::veneers::operator_delete;

/// Prefix of the allocation accepted by [`string_object_owner_destroy`].
///
/// Only this opaque first word and the following [`StringObject`] member are
/// established by the decoded body. The latter is reached with a target word
/// index so it remains at +4 on both ARM and host fixtures.
#[repr(C)]
pub struct StringObjectOwner {
    pub opaque_header: u32,
}

/// string_object_owner_destroy — original: `FUN_0804bd88` @ 0x0804bd88
/// (40 bytes; 12 unconditional `bl` call sites).
///
/// Tears down the embedded `StringObject`, releases its owning allocation, and
/// reports 0. A NULL owner is rejected with the original -50 status.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_object_owner_destroy")]
#[inline(never)]
pub unsafe extern "C" fn string_object_owner_destroy(owner: *mut StringObjectOwner) -> i32 {
    if owner.is_null() {
        return -50;
    }

    let string = owner.cast::<u32>().add(1).cast::<StringObject>();
    let owner = string_object_destroy_veneer(string).cast::<u32>().sub(1).cast::<u8>();
    operator_delete(owner);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectOps, StringObjectVtable, DEFAULT_STRING_OBJECT_OPS,
        STRING_OBJECT_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use std::sync::MutexGuard;

    static mut RELEASED_STRING: usize = 0;

    unsafe extern "C" fn recording_release(string: *mut StringObject) {
        RELEASED_STRING = string as usize;
    }

    struct Bench {
        _heap: MutexGuard<'static, ()>,
        _string_object: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        // Keep the same lock ordering as string_object's release tests.
        let heap = mock_heap();
        let string_object = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            RELEASED_STRING = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS),
                StringObjectOps {
                    release_payload: recording_release,
                },
            );
        }
        Bench {
            _heap: heap,
            _string_object: string_object,
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(STRING_OBJECT_OPS),
                    DEFAULT_STRING_OBJECT_OPS,
                );
            }
        }
    }

    #[repr(align(8))]
    struct OwnerStorage([u8; 32]);

    #[test]
    fn null_owner_returns_minus_50_without_heap_traffic() {
        let _heap = mock_heap();

        assert_eq!(unsafe { string_object_owner_destroy(core::ptr::null_mut()) }, -50);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn destroys_the_word_one_string_then_frees_its_owner() {
        let _bench = bench();
        let mut storage = OwnerStorage([0; 32]);
        // Make owner + 4 naturally aligned for the host's StringObject.
        let owner = unsafe { storage.0.as_mut_ptr().add(4) }.cast::<StringObjectOwner>();
        let string = unsafe { owner.cast::<u32>().add(1).cast::<StringObject>() };
        assert_eq!(string as usize % core::mem::align_of::<StringObject>(), 0);

        unsafe {
            owner.cast::<u32>().write(0xfeed_face);
            string.write(StringObject {
                vtable: 0xdead_beef as *const StringObjectVtable,
                payload: 0xcafe_f00d as *mut u8,
            });

            assert_eq!(string_object_owner_destroy(owner), 0);
            assert_eq!(RELEASED_STRING, string as usize);
            assert_eq!((*string).vtable, &STRING_OBJECT_VTABLE as *const _);
        }
        assert_eq!(free_log(), (1, owner.cast::<u8>(), 2));
    }
}
