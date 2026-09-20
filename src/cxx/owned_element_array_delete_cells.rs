//! `owned_element_array_delete_cells` — retailOS `FUN_083d0568` @ `0x083d0568`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` has 19 ARM words from `push {r4,r5,r6,lr}` at `0x083d0568`
//! through `pop {r4,r5,r6,pc}` at `0x083d05b4`; `0x083d05b8` begins the next
//! independently entered function, so the true size is **76 bytes**. The body
//! has no plain direct `bl`, one predicated direct `blne` to `operator_delete`
//! @ `0x082aad24`, and one unconditional virtual `blx` through slot `+0x40`.
//! Raw whole-image call decoding finds three inbound plain `bl` callers and no
//! predicated direct callers.
//!
//! ## Algorithm
//!
//! When the enable byte at `+0x10` is set, walk signed indices `[0, count)`.
//! The `+0x40` virtual accessor yields a cell; a non-NULL first word is passed
//! directly to tag-2 `operator_delete`. Empty cells are skipped.
//!
//! Deliberate deviation: host fixtures widen the vtable pointer and replace the
//! direct delete with a callback, since firmware u32 vtable words cannot hold
//! x86-64 callbacks and fixture allocations are not retail heap blocks.

use super::owned_element_array_release::{OwnedElementArrayAt, OwnedElementArrayRelease};
#[cfg(not(target_os = "none"))]
use super::owned_element_array_release::OwnedElementArrayReleaseVtable;
use crate::heap::veneers::operator_delete;

#[cfg(not(target_os = "none"))]
pub type OwnedElementArrayDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(ptr: *mut u8) {
    operator_delete(ptr);
}

#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_DELETE: OwnedElementArrayDelete = host_delete;

#[inline(always)]
unsafe fn delete_cell(cell: *mut u32) {
    let allocation = cell.read_volatile() as usize as *mut u8;
    if allocation.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    operator_delete(allocation);
    #[cfg(not(target_os = "none"))]
    OWNED_ELEMENT_ARRAY_DELETE(allocation);
}

/// Releases every populated owned cell while enabled.
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Every non-NULL cell word must be a pointer accepted by `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_delete_cells(this: *mut OwnedElementArrayRelease) {
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
            delete_cell(at(this, index));
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostOwnedElementArrayDeleteCells>();
        if (*host).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*host).count {
            delete_cell(((*(*host).vtable).at)(this, index));
            index += 1;
        }
    }
}

/// Host-only replacement of the target's first word with a native vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedElementArrayDeleteCells {
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
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn element_at(_: *mut OwnedElementArrayRelease, index: i32) -> *mut u32 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETED[DELETE_COUNT] = ptr as usize;
        DELETE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const OwnedElementArrayReleaseVtable) -> HostOwnedElementArrayDeleteCells {
        HostOwnedElementArrayDeleteCells { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OwnedElementArrayReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            INDEX_COUNT = 0;
            DELETE_COUNT = 0;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_delete_cells((&mut fixture(0, 2, &vtable) as *mut HostOwnedElementArrayDeleteCells).cast());
            owned_element_array_delete_cells((&mut fixture(1, 0, &vtable) as *mut HostOwnedElementArrayDeleteCells).cast());
            owned_element_array_delete_cells((&mut fixture(1, -1, &vtable) as *mut HostOwnedElementArrayDeleteCells).cast());
            CELLS = [0; 4];
            owned_element_array_delete_cells((&mut fixture(1, 1, &vtable) as *mut HostOwnedElementArrayDeleteCells).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn deletes_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OwnedElementArrayReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            CELLS = [0x1000, 0, 0x3000, 0];
            INDEX_COUNT = 0;
            DELETE_COUNT = 0;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_delete_cells((&mut fixture(1, 3, &vtable) as *mut HostOwnedElementArrayDeleteCells).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
