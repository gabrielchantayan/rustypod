//! `owned_element_array_release` — retailOS `FUN_083d1bf0` @ `0x083d1bf0`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` is 24 ARM words (`0x083d1bf0..0x083d1c4c`); the next real
//! function starts at `0x083d1c50` with `push {r4,r5,r6,lr}`, so the true size
//! is **96 bytes**. The body has two plain direct `bl` calls (to
//! `opaque_observable_array_destroy` @ `0x083d1df4` and `operator_delete` @
//! `0x082aad24`), no predicated `bl`, and one unconditional virtual `blx`
//! through slot `+0x40`. Whole-image decoding finds three inbound plain `bl`
//! calls (0x08212110, 0x083d1cb0, and 0x083d1d28), and no predicated direct
//! calls.
//!
//! ## Algorithm
//!
//! When the enable byte at `+0x10` is set, walk indices `[0, count)`. The
//! `+0x40` virtual accessor yields a cell; a non-NULL first word is an owned
//! object with an eight-byte allocation header. Destroy its object body at
//! `cell[0] + 8`, then delete the returned object pointer minus eight. Cells
//! with a NULL first word are skipped.
//!
//! Deliberate deviations: host fixtures widen the vtable pointer and replace
//! the two direct calls with seams, since firmware u32 vtable words cannot
//! hold x86-64 callbacks and fixture allocations are not retail heap blocks.

use super::observable_array::ObservableArray;
use super::opaque_observable_array_destroy::opaque_observable_array_destroy;
use crate::heap::veneers::operator_delete;

/// Host representation of virtual slot `+0x40`.
pub type OwnedElementArrayAt = unsafe extern "C" fn(*mut OwnedElementArrayRelease, i32) -> *mut u32;

/// Host vtable representation with the observed indexed-access slot.
#[repr(C)]
pub struct OwnedElementArrayReleaseVtable {
    pub unresolved_00_3c: [usize; 16],
    pub at: OwnedElementArrayAt,
}

/// Target-layout prefix used by the release walk.
#[repr(C)]
pub struct OwnedElementArrayRelease {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
pub type OwnedElementArrayDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type OwnedElementArrayDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destroy(element: *mut u8) -> *mut u8 {
    opaque_observable_array_destroy(element.cast::<ObservableArray>()).cast()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(ptr: *mut u8) {
    operator_delete(ptr);
}

#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_DESTROY: OwnedElementArrayDestroy = host_destroy;
#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_DELETE: OwnedElementArrayDelete = host_delete;

#[inline(always)]
unsafe fn destroy_and_delete(cell: *mut u32) {
    let object = cell.read_volatile() as usize as *mut u8;
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    let object = opaque_observable_array_destroy(object.add(8).cast::<ObservableArray>()).cast::<u8>();
    #[cfg(not(target_os = "none"))]
    let object = OWNED_ELEMENT_ARRAY_DESTROY(object.add(8));

    #[cfg(target_os = "none")]
    operator_delete(object.sub(8));
    #[cfg(not(target_os = "none"))]
    OWNED_ELEMENT_ARRAY_DELETE(object.sub(8));
}

/// Destroys and releases every populated owned element while enabled.
///
/// Original: `FUN_083d1bf0` @ `0x083d1bf0` (96 bytes; 3 inbound plain `bl`
/// calls, no predicated direct callers).
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Every non-NULL cell word must be an allocation-header pointer whose object
/// body at `+8` meets `opaque_observable_array_destroy`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_release(this: *mut OwnedElementArrayRelease) {
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
        let host = this.cast::<HostOwnedElementArrayRelease>();
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
pub struct HostOwnedElementArrayRelease {
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

    unsafe extern "C" fn record_destroy(element: *mut u8) -> *mut u8 {
        DESTROYED[DESTROY_COUNT] = element as usize;
        DESTROY_COUNT += 1;
        element
    }

    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETED[DELETE_COUNT] = ptr as usize;
        DELETE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const OwnedElementArrayReleaseVtable) -> HostOwnedElementArrayRelease {
        HostOwnedElementArrayRelease { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = OwnedElementArrayReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            DELETE_COUNT = 0;
            OWNED_ELEMENT_ARRAY_DESTROY = record_destroy;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_release((&mut fixture(0, 2, &vtable) as *mut HostOwnedElementArrayRelease).cast());
            owned_element_array_release((&mut fixture(1, 0, &vtable) as *mut HostOwnedElementArrayRelease).cast());
            owned_element_array_release((&mut fixture(1, -1, &vtable) as *mut HostOwnedElementArrayRelease).cast());
            CELLS = [0; 4];
            owned_element_array_release((&mut fixture(1, 1, &vtable) as *mut HostOwnedElementArrayRelease).cast());
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
            OWNED_ELEMENT_ARRAY_DESTROY = record_destroy;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_release((&mut fixture(1, 3, &vtable) as *mut HostOwnedElementArrayRelease).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[0x1008, 0x3008]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
