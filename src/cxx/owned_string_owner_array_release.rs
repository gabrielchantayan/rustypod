//! `owned_string_owner_array_release` — retailOS `FUN_083d0ec0` @ `0x083d0ec0`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` has 22 ARM words from `push {r4,r5,r6,lr}` at `0x083d0ec0`
//! through `pop {r4,r5,r6,pc}` at `0x083d0f14`; `0x083d0f18` starts the next
//! independently entered function, so the true size is **88 bytes**. The body
//! has two plain direct `bl` calls (`opaque_string_owner_destroy` @ `0x0826c994`
//! and `operator_delete` @ `0x082aad24`), no predicated `bl`, and one virtual
//! `blx` through vtable slot `+0x40`. Whole-image decoding finds three inbound
//! plain `bl` calls (0x081a293c, 0x083d0f70, and 0x083d0fa8), with no predicated
//! direct callers.
//!
//! ## Algorithm
//!
//! When `enabled` at `+0x10` is nonzero, walk signed indices `[0, count)`. The
//! vtable `+0x40` accessor returns a cell. A non-NULL first word is an allocation
//! header immediately before an opaque string owner: destroy the owner at `+4`,
//! then tag-2 delete the returned pointer minus four. Empty cells are skipped.
//!
//! Deliberate host deviation: the vtable pointer and direct calls are represented
//! by native-width callbacks, because x86-64 function pointers cannot occupy the
//! target's u32 slots; target builds use the recovered direct callees.

use super::owned_element_array_release::{OwnedElementArrayAt, OwnedElementArrayRelease};
#[cfg(not(target_os = "none"))]
use super::owned_element_array_release::OwnedElementArrayReleaseVtable;
use super::opaque_string_owner_destroy::{opaque_string_owner_destroy, OpaqueStringOwner};
use crate::heap::veneers::operator_delete;

#[cfg(not(target_os = "none"))]
pub type OwnedStringOwnerDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type OwnedStringOwnerDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destroy(owner: *mut u8) -> *mut u8 {
    opaque_string_owner_destroy(owner.cast::<OpaqueStringOwner>()).cast()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(ptr: *mut u8) {
    operator_delete(ptr);
}

#[cfg(not(target_os = "none"))]
pub static mut OWNED_STRING_OWNER_DESTROY: OwnedStringOwnerDestroy = host_destroy;
#[cfg(not(target_os = "none"))]
pub static mut OWNED_STRING_OWNER_DELETE: OwnedStringOwnerDelete = host_delete;

#[inline(always)]
unsafe fn destroy_and_delete(cell: *mut u32) {
    let header = cell.read_volatile() as usize as *mut u8;
    if header.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    let owner = opaque_string_owner_destroy(header.add(4).cast::<OpaqueStringOwner>()).cast::<u8>();
    #[cfg(not(target_os = "none"))]
    let owner = OWNED_STRING_OWNER_DESTROY(header.add(4));

    #[cfg(target_os = "none")]
    operator_delete(owner.sub(4));
    #[cfg(not(target_os = "none"))]
    OWNED_STRING_OWNER_DELETE(owner.sub(4));
}

/// Destroys and releases populated opaque string owners while enabled.
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Every non-NULL cell word must be an allocation-header pointer whose owner at
/// `+4` meets `opaque_string_owner_destroy`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_string_owner_array_release(this: *mut OwnedElementArrayRelease) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if base.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = base.add(0x04).cast::<i32>().read_volatile();
        let vtable = base.cast::<u32>().read_volatile() as usize as *const u32;
        let at: OwnedElementArrayAt = core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        let mut index = 0;
        while index < count {
            destroy_and_delete(at(this, index));
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostOwnedStringOwnerArrayRelease>();
        if (*host).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*host).count {
            destroy_and_delete(((*(*host).vtable).at)(this, index));
            index += 1;
        }
    }
}

/// Host-only replacement of the target's first word with a native vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedStringOwnerArrayRelease {
    pub vtable: *const OwnedElementArrayReleaseVtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut DESTROYED: [usize; 4] = [0; 4];
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn element_at(_: *mut OwnedElementArrayRelease, index: i32) -> *mut u32 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }
    unsafe extern "C" fn record_destroy(owner: *mut u8) -> *mut u8 {
        DESTROYED[DESTROY_COUNT] = owner as usize;
        DESTROY_COUNT += 1;
        owner
    }
    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETED[DELETE_COUNT] = ptr as usize;
        DELETE_COUNT += 1;
    }
    fn fixture(enabled: u8, count: i32, vtable: *const OwnedElementArrayReleaseVtable) -> HostOwnedStringOwnerArrayRelease {
        HostOwnedStringOwnerArrayRelease { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OwnedElementArrayReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            DELETE_COUNT = 0;
            OWNED_STRING_OWNER_DESTROY = record_destroy;
            OWNED_STRING_OWNER_DELETE = record_delete;
            owned_string_owner_array_release((&mut fixture(0, 2, &vtable) as *mut HostOwnedStringOwnerArrayRelease).cast());
            owned_string_owner_array_release((&mut fixture(1, 0, &vtable) as *mut HostOwnedStringOwnerArrayRelease).cast());
            owned_string_owner_array_release((&mut fixture(1, -1, &vtable) as *mut HostOwnedStringOwnerArrayRelease).cast());
            CELLS = [0; 4];
            owned_string_owner_array_release((&mut fixture(1, 1, &vtable) as *mut HostOwnedStringOwnerArrayRelease).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(DESTROY_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn destroys_then_deletes_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OwnedElementArrayReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            CELLS = [0x1000, 0, 0x3000, 0];
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            DELETE_COUNT = 0;
            OWNED_STRING_OWNER_DESTROY = record_destroy;
            OWNED_STRING_OWNER_DELETE = record_delete;
            owned_string_owner_array_release((&mut fixture(1, 3, &vtable) as *mut HostOwnedStringOwnerArrayRelease).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[0x1004, 0x3004]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
