//! `owned_string_object_array_release` — retailOS `FUN_0839ca9c` @ `0x0839ca9c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains 22 ARM words from `push {r4,r5,r6,lr}` at
//! `0x0839ca9c` through `pop {r4,r5,r6,pc}` at `0x0839caf0`; the next
//! independently entered function starts at `0x0839caf4`, so the true size is
//! **88 bytes**. The body has two plain direct `bl` calls: `FUN_081b022c`,
//! which adds eight bytes to the owner, calls `string_object_destroy` @
//! `0x08277484`, then subtracts eight; and `operator_delete` @ `0x082aad24`.
//! It has no predicated direct `bl` calls and one virtual `blx` through vtable
//! slot `+0x40`.
//!
//! ## Algorithm
//!
//! When byte `+0x28` is set, visit signed indexes `[0, count)` through the
//! collection's vtable slot `+0x40`. For each returned cell with a non-NULL
//! first word, destroy the owner's embedded `StringObject` at `+0x08`, then
//! tag-2-delete the owner allocation. Empty cells are skipped.
//!
//! ## Deliberate deviations
//!
//! Host vtable pointers and cell pointers are native-width; target code reads
//! the verified 32-bit words at their retail offsets. This preserves the ABI
//! while allowing host fixtures to use ordinary Rust callbacks.

use crate::cxx::string_object::string_object_destroy;
#[cfg(test)]
use crate::cxx::string_object::StringObject;
use crate::heap::veneers::operator_delete;

const ELEMENT_AT_SLOT: usize = 0x40 / 4;
type ElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedStringObjectArrayReleaseVtable {
    pub unresolved_00_3c: [usize; ELEMENT_AT_SLOT],
    pub element_at: ElementAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedStringObjectArrayRelease {
    pub vtable: *const HostOwnedStringObjectArrayReleaseVtable,
    pub count: i32,
    pub unresolved_0c_27: [u8; 0x1c],
    pub enabled: u8,
}

#[inline(always)]
unsafe fn destroy_and_delete(owner: *mut u8) {
    if owner.is_null() {
        return;
    }
    string_object_destroy(owner.add(8).cast());
    operator_delete(owner);
}

/// Destroys and releases every populated StringObject owner while enabled.
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Each non-NULL cell word must be an owner allocation containing a
/// StringObject at `+0x08`, accepted by `operator_delete` after destruction.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_string_object_array_release(this: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if this.add(0x28).read_volatile() == 0 {
            return;
        }
        let count = this.add(4).cast::<i32>().read_volatile();
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: ElementAt = core::mem::transmute(vtable.add(ELEMENT_AT_SLOT).read_volatile() as usize);
        let mut index = 0;
        while index < count {
            let owner = element_at(this, index).cast::<u32>().read_volatile() as usize as *mut u8;
            destroy_and_delete(owner);
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let collection = this.cast::<HostOwnedStringObjectArrayRelease>();
        if (*collection).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*collection).count {
            let element_at = (*(*collection).vtable).element_at;
            let owner = (element_at(this, index).cast::<*mut u8>()).read();
            destroy_and_delete(owner);
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUPS: [i32; 4] = [0; 4];
    static mut LOOKUP_COUNT: usize = 0;
    static mut CELLS: [*mut u8; 4] = [core::ptr::null_mut(); 4];

    unsafe extern "C" fn element_at(_: *mut u8, index: i32) -> *mut u8 {
        LOOKUPS[LOOKUP_COUNT] = index;
        LOOKUP_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize).cast()
    }

    #[repr(C)]
    struct OwnerFixture { header: [u32; 2], string: StringObject }

    struct Bench { _lock: MutexGuard<'static, ()>, _heap: MutexGuard<'static, ()> }

    fn bench() -> Bench {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { LOOKUPS = [0; 4]; LOOKUP_COUNT = 0; CELLS = [core::ptr::null_mut(); 4]; }
        Bench { _lock: lock, _heap: crate::heap::veneers::tests::mock_heap() }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostOwnedStringObjectArrayReleaseVtable) -> HostOwnedStringObjectArrayRelease {
        HostOwnedStringObjectArrayRelease { vtable, count, unresolved_0c_27: [0; 0x1c], enabled }
    }

    #[test]
    fn inactive_or_nonpositive_count_has_no_virtual_lookup() {
        let _bench = bench();
        let vtable = HostOwnedStringObjectArrayReleaseVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        unsafe {
            owned_string_object_array_release((&mut fixture(0, 2, &vtable) as *mut HostOwnedStringObjectArrayRelease).cast());
            owned_string_object_array_release((&mut fixture(1, 0, &vtable) as *mut HostOwnedStringObjectArrayRelease).cast());
            owned_string_object_array_release((&mut fixture(1, -1, &vtable) as *mut HostOwnedStringObjectArrayRelease).cast());
            assert_eq!(LOOKUP_COUNT, 0);
            assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        }
    }

    #[test]
    fn skips_empty_cells_and_releases_each_populated_cell_in_order() {
        let _bench = bench();
        let vtable = HostOwnedStringObjectArrayReleaseVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        let mut first = OwnerFixture { header: [0; 2], string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() } };
        let mut third = OwnerFixture { header: [0; 2], string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() } };
        unsafe {
            CELLS = [(&mut first as *mut OwnerFixture).cast(), core::ptr::null_mut(), (&mut third as *mut OwnerFixture).cast(), core::ptr::null_mut()];
            owned_string_object_array_release((&mut fixture(1, 3, &vtable) as *mut HostOwnedStringObjectArrayRelease).cast());
            assert_eq!(&LOOKUPS[..LOOKUP_COUNT], &[0, 1, 2]);
            assert_eq!(crate::heap::veneers::tests::free_log(), (2, &mut third as *mut _ as *mut u8, 2));
        }
    }
}
