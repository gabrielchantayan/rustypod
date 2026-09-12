//! Constructor for a vtable-bearing record with a retained shared handle.
//!
//! ## Original: `FUN_083e78b4` @ 0x083e78b4 (68 bytes)
//!
//! The raw extent is 60 instruction bytes plus the two literal-pool words at
//! 0x083e78f0 and 0x083e78f4; the next function starts at 0x083e78f8.
//! Decoding every ARM B/BL immediate in `osos.dec` finds eight inbound direct
//! calls, all unconditional `bl` (0x082a782c, 0x082a7dc4, 0x082a8f80,
//! 0x083d8044, 0x083d8074, 0x083d80d4, 0x083dae68, and 0x083dae9c), with no
//! predicated forms or direct tail branches.
//!
//! The constructor first plants descriptor 0x089a8aac, invokes the shared
//! handle initializer on its `+0x18` word, clears the six words at
//! `+0x1c..+0x30`, then replaces the descriptor with 0x089a8b04 and returns
//! the incoming storage. It deliberately preserves words `+0x04..+0x14` and
//! the shared-handle initializer's `+0x18` result.
//!
use crate::cxx::shared_handle_initialize::shared_handle_initialize;

/// The descriptor written before calling `FUN_082a8b68`.
pub const SHARED_HANDLE_BASE_DESCRIPTOR: u32 = 0x089a_8aac;
/// The descriptor installed after the shared handle is initialized.
pub const SHARED_HANDLE_DESCRIPTOR: u32 = 0x089a_8b04;

/// Target-layout record constructed by [`vtable_shared_handle_construct`].
#[repr(C)]
pub struct VtableSharedHandle {
    /// +0x00: base descriptor before the shared-handle initializer, derived
    /// descriptor on return.
    pub descriptor: u32,
    /// +0x04..+0x14: not written by this constructor.
    pub preserved: [u32; 5],
    /// +0x18: global shared-object handle written by `FUN_082a8b68`.
    pub shared_handle: u32,
    /// +0x1c..+0x30: cleared after the shared-handle initializer.
    pub cleared: [u32; 6],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 52] = [0; core::mem::size_of::<VtableSharedHandle>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 24] = [0; core::mem::offset_of!(VtableSharedHandle, shared_handle)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 28] = [0; core::mem::offset_of!(VtableSharedHandle, cleared)];


/// `vtable_shared_handle_construct` — original `FUN_083e78b4` @
/// `0x083e78b4` (60 code bytes + 8 literal-pool bytes).
///
/// Installs the base descriptor, initializes the `+0x18` shared handle, clears
/// the trailing six words, installs the derived descriptor, and returns
/// `storage`. `storage` must be valid for one aligned [`VtableSharedHandle`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_shared_handle_construct(
    storage: *mut VtableSharedHandle,
) -> *mut VtableSharedHandle {
    (*storage).descriptor = SHARED_HANDLE_BASE_DESCRIPTOR;
    shared_handle_initialize(core::ptr::addr_of_mut!((*storage).shared_handle));
    (*storage).cleared = [0; 6];
    (*storage).descriptor = SHARED_HANDLE_DESCRIPTOR;
    storage
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::shared_handle_initialize::{
        SHARED_HANDLE_BOOTSTRAP, SHARED_HANDLE_GLOBAL, SHARED_HANDLE_INITIALIZE_TEST_LOCK,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::LazyLock;

    const OBJECT_LEN: usize = 0x40;
    static OBJECT: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VTABLE_SHARED_HANDLE_CONSTRUCT, OBJECT_LEN).map(|pointer| pointer as usize)
    });

    unsafe extern "C" fn unexpected_bootstrap() {
        panic!("constructor fixture must install a shared object");
    }

    unsafe fn reset_shared_object() -> Option<*mut u32> {
        let object = (*OBJECT)? as *mut u32;
        core::ptr::write_bytes(object.cast::<u8>(), 0, OBJECT_LEN);
        object.add(7).write(0);
        SHARED_HANDLE_GLOBAL = object as usize as u32;
        SHARED_HANDLE_BOOTSTRAP = unexpected_bootstrap;
        Some(object)
    }

    #[test]
    fn initializes_only_the_observed_words_and_returns_storage() {
        let _guard = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        unsafe {
            let Some(object) = reset_shared_object() else {
                assert!(note_missing_u32_fixture("cxx/vtable_shared_handle_construct"));
                return;
            };
            let mut record = VtableSharedHandle {
                descriptor: 0x1111_2222,
                preserved: [0x3333_4444, 0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc],
                shared_handle: 0xdddd_eeee,
                cleared: [0x0123_4567; 6],
            };

            let returned = vtable_shared_handle_construct(addr_of_mut!(record));

            assert_eq!(returned, addr_of_mut!(record));
            assert_eq!(record.descriptor, SHARED_HANDLE_DESCRIPTOR);
            assert_eq!(record.preserved, [0x3333_4444, 0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc]);
            assert_eq!(record.shared_handle, object as usize as u32);
            assert_eq!(object.add(7).read(), 1);
            assert_eq!(record.cleared, [0; 6]);
        }
    }
}
