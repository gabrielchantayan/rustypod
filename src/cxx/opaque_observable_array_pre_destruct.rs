//! `opaque_observable_array_pre_destruct` — retailOS `FUN_083d0834` @ `0x083d0834`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` decodes twenty-two A32 words from `0x083d0834` through
//! `0x083d0888`; `push {r4,r5,r6,lr}` at `0x083d088c` begins the next real
//! function, so the true size is **88 bytes**. The body has two unconditional
//! plain direct `bl` calls, to `unidentified_string_pair_destroy` @
//! `0x0819b5fc` and `operator_delete` @ `0x082aad24`, zero predicated direct
//! `bl` calls, and one unconditional virtual `blx` through slot `+0x40`.
//!
//! ## Algorithm
//!
//! When the enable byte at `+0x10` is nonzero, walks signed indices
//! `[0, count)`. It calls the `+0x40` virtual accessor for each index and, for
//! each non-null allocation body in the returned cell, destroys it then deletes
//! the pointer returned by that destructor.
//!
//! Deliberate deviations: host fixtures widen the vtable pointer and use seams
//! for the unresolved destructor and `operator_delete`; target builds retain
//! target-width words and call both verified firmware targets directly.

use crate::heap::veneers::operator_delete;

const ENABLED_OFFSET: usize = 0x10;
const CELL_AT_SLOT: usize = 0x40 / 4;
const UNIDENTIFIED_STRING_PAIR_DESTROY_ADDRESS: usize = 0x0819_b5fc;

pub type OpaqueObservableArrayCellAt = unsafe extern "C" fn(*mut u32, i32) -> *mut u32;
pub type UnidentifiedStringPairDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
/// Host representation of the virtual accessor consumed by this loop.
#[repr(C)]
pub struct OpaqueObservableArrayPreDestructVtable {
    pub unresolved_00_3c: [usize; CELL_AT_SLOT],
    pub cell_at: unsafe extern "C" fn(*mut HostOpaqueObservableArrayPreDestruct, i32) -> *mut u32,
}

/// Host-only widening of the target vtable word.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArrayPreDestruct {
    pub vtable: *const OpaqueObservableArrayPreDestructVtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_allocation_body(body: *mut u8) -> *mut u8 {
    let destroy: UnidentifiedStringPairDestroy = unsafe {
        core::mem::transmute::<usize, UnidentifiedStringPairDestroy>(UNIDENTIFIED_STRING_PAIR_DESTROY_ADDRESS)
    };
    unsafe { destroy(body) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_body: *mut u8) -> *mut u8 {
    panic!("install opaque observable-array pre-destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_body: *mut u8) {
    panic!("install opaque observable-array pre-destructor host seams before calling this port")
}

/// Host replacements for the unresolved destructor and `operator_delete`.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_PRE_DESTRUCT_OPS: (UnidentifiedStringPairDestroy, unsafe extern "C" fn(*mut u8)) =
    (missing_destroy, missing_delete);

/// Destroys and deletes each populated cell while the array is enabled.
///
/// # Safety
///
/// `this` must point to a readable observable-array prefix. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_pre_destruct(this: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let bytes = this.cast::<u8>();
        if unsafe { bytes.add(ENABLED_OFFSET).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { this.add(1).cast::<i32>().read_volatile() };
        let vtable = unsafe { this.read_volatile() } as usize as *const u32;
        let cell_at: OpaqueObservableArrayCellAt = unsafe {
            core::mem::transmute(vtable.add(CELL_AT_SLOT).read_volatile() as usize)
        };
        let mut index = 0;
        while index < count {
            let cell = unsafe { cell_at(this, index) };
            let body = unsafe { cell.read_volatile() } as usize as *mut u8;
            if !body.is_null() {
                unsafe { operator_delete(destroy_allocation_body(body)) };
            }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostOpaqueObservableArrayPreDestruct>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let cell = unsafe { ((*(*host).vtable).cell_at)(host, index) };
            let body = unsafe { cell.read_volatile() } as usize as *mut u8;
            if !body.is_null() {
                let (destroy, delete) = unsafe {
                    core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_PRE_DESTRUCT_OPS))
                };
                unsafe { delete(destroy(body)) };
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];
    static mut EVENTS: [(u8, usize); 8] = [(0, 0); 8];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn cell_at(_: *mut HostOpaqueObservableArrayPreDestruct, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn destroy(body: *mut u8) -> *mut u8 {
        unsafe { EVENTS[EVENT_COUNT] = (1, body as usize); EVENT_COUNT += 1; body.wrapping_add(8) }
    }

    unsafe extern "C" fn delete(body: *mut u8) {
        unsafe { EVENTS[EVENT_COUNT] = (2, body as usize); EVENT_COUNT += 1; }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const OpaqueObservableArrayPreDestructVtable) -> HostOpaqueObservableArrayPreDestruct {
        HostOpaqueObservableArrayPreDestruct { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_counts() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OpaqueObservableArrayPreDestructVtable { unresolved_00_3c: [0; CELL_AT_SLOT], cell_at };
            INDEX_COUNT = 0; EVENT_COUNT = 0;
            OPAQUE_OBSERVABLE_ARRAY_PRE_DESTRUCT_OPS = (destroy, delete);
            opaque_observable_array_pre_destruct((&mut fixture(0, 3, &vtable) as *mut HostOpaqueObservableArrayPreDestruct).cast());
            opaque_observable_array_pre_destruct((&mut fixture(1, 0, &vtable) as *mut HostOpaqueObservableArrayPreDestruct).cast());
            opaque_observable_array_pre_destruct((&mut fixture(1, -1, &vtable) as *mut HostOpaqueObservableArrayPreDestruct).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(EVENT_COUNT, 0);
        }
    }

    #[test]
    fn destroys_then_deletes_only_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OpaqueObservableArrayPreDestructVtable { unresolved_00_3c: [0; CELL_AT_SLOT], cell_at };
            CELLS = [0x1000, 0, 0x3000, 0]; INDEX_COUNT = 0; EVENT_COUNT = 0;
            OPAQUE_OBSERVABLE_ARRAY_PRE_DESTRUCT_OPS = (destroy, delete);
            opaque_observable_array_pre_destruct((&mut fixture(1, 3, &vtable) as *mut HostOpaqueObservableArrayPreDestruct).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[(1, 0x1000), (2, 0x1008), (1, 0x3000), (2, 0x3008)]);
        }
    }
}
