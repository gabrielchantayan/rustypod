//! `pending_object_release` — releases one pending opaque object from an
//! application-owned slot.
//!
//! Original: `FUN_081db860` @ `0x081db860` (60 bytes exactly,
//! `0x081db860..0x081db89b`). The following pending-object pair helper opens at
//! `0x081db89c`, establishing the boundary. A complete raw ARM B/BL-immediate
//! scan finds four plain inbound `bl` calls (`0x081daf04`, `0x081dbc28`,
//! `0x081dbfcc`, and `0x081dc1ec`) and one predicated `bleq` at `0x081dbc48`.
//! The body has two plain `bl` instructions and no predicated calls.
//!
//! # Algorithm
//!
//! Read the pending opaque object at `owner+0x1b8`; if present, set its byte
//! `+0x60` release flag, reload the slot, then destruct and tag-2 free the
//! reloaded object when non-NULL. Clear both adjacent owner words at `+0x1b4`
//! and `+0x1b8` on every path.
//!
//! # Deliberate deviations
//!
//! The opaque destructor at `0x0828e5b0` remains unported. This port reuses the
//! verified target-address/host-test seam from `pending_object_pair_release`;
//! no class identity is inferred.

use core::ptr::addr_of_mut;

use super::pending_object_pair_release::PENDING_OBJECT_DESTRUCT;

pub const PENDING_STATE: usize = 0x1b4;
pub const PENDING_OBJECT: usize = 0x1b8;
pub const PENDING_OBJECT_RELEASE_FLAG: usize = 0x60;

/// Releases the pending opaque object and clears its two-word owner state.
///
/// # Safety
/// `owner` must point to writable, four-byte-aligned storage through `+0x1b8`.
/// A non-zero pending-object word must name a live tag-2 heap allocation
/// accepted by the opaque destructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pending_object_release(owner: *mut u8) {
    let object = unsafe { (owner.add(PENDING_OBJECT) as *const u32).read_volatile() } as *mut u8;
    if !object.is_null() {
        unsafe { (object.add(PENDING_OBJECT_RELEASE_FLAG) as *mut u8).write_volatile(1) };
    }

    let object = unsafe { (owner.add(PENDING_OBJECT) as *const u32).read_volatile() } as *mut u8;
    if !object.is_null() {
        let destruct = unsafe { addr_of_mut!(PENDING_OBJECT_DESTRUCT).read_volatile() };
        unsafe {
            destruct(object);
            crate::heap::veneers::operator_delete(object);
        }
    }

    unsafe {
        (owner.add(PENDING_STATE) as *mut u32).write_volatile(0);
        (owner.add(PENDING_OBJECT) as *mut u32).write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::pending_object_pair_release::{missing_destruct_0828e5b0, PENDING_OBJECT_DESTRUCT_LOCK};
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut DESTRUCTED: Vec<*mut u8> = Vec::new();
    const OBJECT_SLAB_LEN: usize = 0x100;

    unsafe extern "C" fn recording_destruct(object: *mut u8) {
        unsafe { (*addr_of_mut!(DESTRUCTED)).push(object) };
    }

    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let destruct_guard = PENDING_OBJECT_DESTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            addr_of_mut!(PENDING_OBJECT_DESTRUCT).write_volatile(recording_destruct);
            (*addr_of_mut!(DESTRUCTED)).clear();
        }
        (destruct_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { addr_of_mut!(PENDING_OBJECT_DESTRUCT).write_volatile(missing_destruct_0828e5b0) };
        drop(guards);
    }

    #[repr(align(4))]
    struct Owner([u8; PENDING_OBJECT + 4]);

    fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn object_slab() -> Option<*mut u8> {
        try_map_u32_slab(crate::testing::hints::PENDING_OBJECT_RELEASE, OBJECT_SLAB_LEN)
    }

    #[test]
    fn marks_destructs_and_frees_object_then_clears_owner_state() {
        let guards = mock();
        let Some(object) = object_slab() else {
            restore(guards);
            assert!(note_missing_u32_fixture("app::pending_object_release"));
            return;
        };
        let mut owner = Owner([0xa5; PENDING_OBJECT + 4]);
        put_word(&mut owner.0, PENDING_STATE, 0xfeed_beef);
        put_word(&mut owner.0, PENDING_OBJECT, object as usize as u32);

        unsafe { pending_object_release(owner.0.as_mut_ptr()) };

        assert_eq!(unsafe { object.add(PENDING_OBJECT_RELEASE_FLAG).read_volatile() }, 1);
        unsafe { assert_eq!(*core::ptr::addr_of!(DESTRUCTED), std::vec![object]) };
        assert_eq!(free_log(), (1, object, 2));
        assert_eq!(&owner.0[PENDING_STATE..PENDING_OBJECT + 4], &[0; 8]);
        restore(guards);
    }

    #[test]
    fn null_object_skips_release_and_still_clears_owner_state() {
        let guards = mock();
        let mut owner = Owner([0xa5; PENDING_OBJECT + 4]);
        put_word(&mut owner.0, PENDING_STATE, 0xfeed_beef);
        put_word(&mut owner.0, PENDING_OBJECT, 0);

        unsafe { pending_object_release(owner.0.as_mut_ptr()) };

        unsafe { assert!((*core::ptr::addr_of!(DESTRUCTED)).is_empty()) };
        assert_eq!(free_log().0, 0);
        assert_eq!(&owner.0[PENDING_STATE..PENDING_OBJECT + 4], &[0; 8]);
        restore(guards);
    }
}
