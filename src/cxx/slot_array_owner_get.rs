//! Checked pointer-slot getter — original: `FUN_081ef308` @ `0x081ef308`.
//!
//! Raw `osos.dec` is exactly nine ARM words (36 bytes),
//! `0x081ef308..0x081ef32c`; the next independently entered function begins
//! with `push {r4,r5,r6,lr}` at `0x081ef32c`. The body makes one outbound
//! plain `bl` to `slot_array_index_in_bounds` (`0x083d4db8`) and no predicated
//! `bl` calls. Four inbound calls are all plain unconditional `bl` at
//! `0x081eeff8`, `0x081ef03c`, `0x081ef078`, and `0x081ef0b0`; no predicated
//! `bl` form targets this address.
//!
//! Algorithm: load the owner's slot-array pointer at +0x0c, call the shared
//! bounds guard, and return `storage[index]` when it accepts the signed index;
//! otherwise return zero. Deliberate deviation: volatile target-word loads
//! retain the observed ARM memory accesses and prevent a host-width pointer
//! from changing the +0x0c layout.

use super::slot_array_index_in_bounds::{slot_array_index_in_bounds, SlotArray};

/// Opaque owner whose pointer-slot array is held at target offset +0x0c.
#[repr(C)]
pub struct SlotArrayOwner {
    pub opaque_00: u32,
    pub opaque_04: u32,
    pub opaque_08: u32,
    pub slots: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SlotArrayOwner, slots)];

/// slot_array_owner_get — original: `FUN_081ef308` @ `0x081ef308`
/// (36 bytes; 4 inbound plain `bl` call sites, 0 predicated; one outbound
/// plain `bl`). Returns `slots.storage[index]` when `index` is in bounds,
/// otherwise zero.
///
/// # Safety
///
/// `owner` must point to a readable owner and its +0x0c word must name a
/// readable [`SlotArray`]. For an in-range index, that array's storage word
/// must name a readable `u32` element array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_owner_get(owner: *const SlotArrayOwner, index: i32) -> u32 {
    let slots = core::ptr::read_volatile(core::ptr::addr_of!((*owner).slots)) as usize
        as *const SlotArray;
    if slot_array_index_in_bounds(slots, index) == 0 {
        return 0;
    }
    let storage = core::ptr::read_volatile(core::ptr::addr_of!((*slots).storage)) as usize
        as *const u32;
    core::ptr::read_volatile(storage.add(index as usize))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const SLOT_ARRAY_AT: usize = 0x100;
    const STORAGE_AT: usize = 0x200;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SLOT_ARRAY_OWNER_GET, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture(capacity: i32, storage: u32) -> Option<SlotArrayOwner> {
        let base = (*FIXTURE)? as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        let slots = base.add(SLOT_ARRAY_AT).cast::<SlotArray>();
        slots.write(SlotArray { storage, capacity, count: 0 });
        Some(SlotArrayOwner {
            opaque_00: 0,
            opaque_04: 0,
            opaque_08: 0,
            slots: slots as usize as u32,
        })
    }

    #[test]
    fn returns_the_selected_target_word() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(mut owner) = (unsafe { fixture(3, 0) }) else {
            assert!(note_missing_u32_fixture("cxx/slot_array_owner_get"));
            return;
        };
        let base = (*FIXTURE).unwrap() as *mut u8;
        let storage = unsafe { base.add(STORAGE_AT).cast::<u32>() };
        unsafe {
            storage.add(0).write(0x1111_1111);
            storage.add(1).write(0x2222_2222);
            storage.add(2).write(0x3333_3333);
            (*(owner.slots as usize as *mut SlotArray)).storage = storage as usize as u32;
            assert_eq!(slot_array_owner_get(&owner, 0), 0x1111_1111);
            assert_eq!(slot_array_owner_get(&owner, 2), 0x3333_3333);
            owner.opaque_00 = 0xffff_ffff;
        }
    }

    #[test]
    fn rejects_negative_and_capacity_boundary_without_reading_storage() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(owner) = (unsafe { fixture(2, 0) }) else {
            assert!(note_missing_u32_fixture("cxx/slot_array_owner_get"));
            return;
        };
        unsafe {
            assert_eq!(slot_array_owner_get(&owner, -1), 0);
            assert_eq!(slot_array_owner_get(&owner, i32::MIN), 0);
            assert_eq!(slot_array_owner_get(&owner, 2), 0);
            assert_eq!(slot_array_owner_get(&owner, i32::MAX), 0);
        }
    }
}
