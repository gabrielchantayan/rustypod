//! `pending_object_pair_release` — releases two pending opaque objects from an
//! application-owned pair.
//!
//! Original: `FUN_081db89c` @ `0x081db89c` (100 bytes exactly,
//! `0x081db89c..0x081db8ff`). The following two-word helper begins at
//! `0x081db900`, establishing the boundary. Five plain `bl` call sites
//! (`0x081daeec`, `0x081db910`, `0x081dbc20`, `0x081dbfc4`, `0x081dc1e4`)
//! and no predicated `bl` call sites target this function. The body itself has
//! four plain `bl` instructions and no predicated calls: two each to the
//! opaque destructor @ `0x0828e5b0` and tag-2 `operator_delete` @
//! `0x082aad24`.
//!
//! # Algorithm
//!
//! Set byte `+0x60` in each non-NULL pending object at `+0x1a0` and `+0x1a4`.
//! Then, in field order, destruct and free each installed object. Finally clear
//! the adjacent four-word pending-object state at `+0x198..+0x1a4`.
//!
//! # Deliberate deviations
//!
//! The opaque destructor at `0x0828e5b0` is unported. A volatile seam calls its
//! verified firmware address on target and is replaceable by host tests; its
//! class identity is deliberately not inferred.

use core::ptr::addr_of_mut;

pub const PENDING_STATE: usize = 0x198;
pub const FIRST_PENDING_OBJECT: usize = 0x1a0;
pub const SECOND_PENDING_OBJECT: usize = 0x1a4;
pub const PENDING_OBJECT_RELEASE_FLAG: usize = 0x60;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destruct_0828e5b0(object: *mut u8) {
    let destruct: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0828e5b0usize) };
    unsafe { destruct(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destruct_0828e5b0(_object: *mut u8) {
    panic!("pending_object_pair_release requires destructor 0x0828e5b0")
}

/// Opaque object destructor @ `0x0828e5b0`.
///
/// The target default invokes the verified firmware address. Host tests replace
/// this seam because that function has not yet been ported.
#[cfg(target_os = "none")]
pub static mut PENDING_OBJECT_DESTRUCT: unsafe extern "C" fn(*mut u8) = firmware_destruct_0828e5b0;
#[cfg(not(target_os = "none"))]
pub static mut PENDING_OBJECT_DESTRUCT: unsafe extern "C" fn(*mut u8) = missing_destruct_0828e5b0;

/// Releases both pending objects and clears their four-word owner state.
///
/// # Safety
/// `owner` must point to writable, four-byte-aligned storage through `+0x1a8`.
/// Each non-zero pending-object word must name a live tag-2 heap allocation
/// accepted by the opaque destructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pending_object_pair_release(owner: *mut u8) {
    for offset in [FIRST_PENDING_OBJECT, SECOND_PENDING_OBJECT] {
        let object = unsafe { (owner.add(offset) as *const u32).read_volatile() } as *mut u8;
        if !object.is_null() {
            unsafe { (object.add(PENDING_OBJECT_RELEASE_FLAG) as *mut u8).write_volatile(1) };
        }
    }

    for offset in [FIRST_PENDING_OBJECT, SECOND_PENDING_OBJECT] {
        let object = unsafe { (owner.add(offset) as *const u32).read_volatile() } as *mut u8;
        if !object.is_null() {
            let destruct = unsafe { addr_of_mut!(PENDING_OBJECT_DESTRUCT).read_volatile() };
            unsafe {
                destruct(object);
                crate::heap::veneers::operator_delete(object);
            }
        }
    }

    for offset in (PENDING_STATE..=SECOND_PENDING_OBJECT).step_by(4) {
        unsafe { (owner.add(offset) as *mut u32).write_volatile(0) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static mut DESTRUCTED: Vec<*mut u8> = Vec::new();

    const OBJECT_SLAB_LEN: usize = 0x100;
    const SECOND_OBJECT_OFFSET: usize = 0x80;

    unsafe extern "C" fn recording_destruct(object: *mut u8) {
        unsafe { (*addr_of_mut!(DESTRUCTED)).push(object) };
    }

    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let release_guard = RELEASE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            addr_of_mut!(PENDING_OBJECT_DESTRUCT).write_volatile(recording_destruct);
            (*addr_of_mut!(DESTRUCTED)).clear();
        }
        (release_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { addr_of_mut!(PENDING_OBJECT_DESTRUCT).write_volatile(missing_destruct_0828e5b0) };
        drop(guards);
    }

    #[repr(align(4))]
    struct Owner([u8; SECOND_PENDING_OBJECT + 4]);

    fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn object_slab() -> Option<*mut u8> {
        try_map_u32_slab(crate::testing::hints::PENDING_OBJECT_PAIR_RELEASE, OBJECT_SLAB_LEN)
    }

    #[test]
    fn releases_both_objects_in_field_order_then_clears_all_state() {
        let guards = mock();
        let Some(objects) = object_slab() else {
            restore(guards);
            assert!(note_missing_u32_fixture("app::pending_object_pair_release"));
            return;
        };
        let mut owner = Owner([0xa5; SECOND_PENDING_OBJECT + 4]);
        let first = objects;
        let second = unsafe { objects.add(SECOND_OBJECT_OFFSET) };
        put_word(&mut owner.0, FIRST_PENDING_OBJECT, first as usize as u32);
        put_word(&mut owner.0, SECOND_PENDING_OBJECT, second as usize as u32);

        unsafe { pending_object_pair_release(owner.0.as_mut_ptr()) };

        assert_eq!(
            unsafe { first.add(PENDING_OBJECT_RELEASE_FLAG).read_volatile() },
            1,
            "first pending object is marked before destruction"
        );
        assert_eq!(
            unsafe { second.add(PENDING_OBJECT_RELEASE_FLAG).read_volatile() },
            1,
            "second pending object is marked before destruction"
        );
        unsafe {
            assert_eq!(*core::ptr::addr_of!(DESTRUCTED), std::vec![first, second]);
        }
        let (frees, freed, tag) = free_log();
        assert_eq!((frees, freed, tag), (2, second, 2));
        for offset in (PENDING_STATE..=SECOND_PENDING_OBJECT).step_by(4) {
            assert_eq!(&owner.0[offset..offset + 4], &[0; 4], "state word +{offset:#x}");
        }
        restore(guards);
    }

    #[test]
    fn null_entries_skip_release_but_still_clear_all_four_words() {
        let guards = mock();
        let mut owner = Owner([0xa5; SECOND_PENDING_OBJECT + 4]);
        put_word(&mut owner.0, FIRST_PENDING_OBJECT, 0);
        put_word(&mut owner.0, SECOND_PENDING_OBJECT, 0);
        unsafe { pending_object_pair_release(owner.0.as_mut_ptr()) };

        unsafe { assert!((*core::ptr::addr_of!(DESTRUCTED)).is_empty()) };
        assert_eq!(free_log().0, 0);
        for offset in (PENDING_STATE..=SECOND_PENDING_OBJECT).step_by(4) {
            assert_eq!(&owner.0[offset..offset + 4], &[0; 4], "state word +{offset:#x}");
        }
        restore(guards);
    }
}

