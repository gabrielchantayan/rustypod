//! `opaque_observable_array_dispose_elements` — retailOS `FUN_083d0924` @
//! `0x083d0924`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` has 22 ARM words from `push {r4,r5,r6,lr}` at `0x083d0924`
//! through `pop {r4,r5,r6,pc}` at `0x083d0978`; `0x083d097c` begins the next
//! independent function, so the true size is **88 bytes**. The body contains
//! one unconditional virtual `blx` through array-vtable slot `+0x40` and one
//! predicated `blxne` through each element vtable's `+0x04` slot; it contains
//! no direct `bl` instructions. There are three inbound plain `bl` sites
//! (0x0815d518, 0x083d09cc, and 0x083d09e4), with no predicated direct callers.
//!
//! ## Algorithm
//!
//! If the byte at `+0x10` is nonzero, walk signed indices `[0, count)`. Each
//! array-vtable `+0x40` lookup yields a cell whose first word is an optional
//! element pointer. Non-NULL elements receive their vtable `+0x04` operation.
//!
//! Deliberate host deviation: native pointers and callbacks replace the
//! target's 32-bit vtable words; target builds preserve the observed volatile
//! target-width loads and virtual call sequence.

#[cfg(target_os = "none")]
type ElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u32;
#[cfg(target_os = "none")]
type ElementRelease = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub type HostElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut HostElementCell;
#[cfg(not(target_os = "none"))]
pub type HostElementRelease = unsafe extern "C" fn(*mut u8);

/// Host-only representation of the array callback at target vtable offset `+0x40`.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArrayVtable {
    pub unresolved_00_3c: [usize; 16],
    pub element_at: HostElementAt,
}

/// Host-only replacement for the target-width array prefix.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArray {
    pub vtable: *const HostOpaqueObservableArrayVtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

/// Host-only representation of an array cell's optional element word.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HostElementCell {
    pub element: *mut u8,
}

/// Host-only representation of an element whose release operation is at `+0x04`.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElement {
    pub vtable: *const HostElementVtable,
}

/// Host-only element vtable prefix.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElementVtable {
    pub unresolved_00: usize,
    pub release: HostElementRelease,
}

/// Disposes each populated element while the opaque observable array is enabled.
///
/// # Safety
///
/// `this` must point to a readable array prefix. When enabled, its vtable slot
/// `+0x40` must accept `(this, index)` and return a readable cell; every non-NULL
/// cell element must have a readable vtable and callable operation at `+0x04`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_dispose_elements(this: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if this.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = this.add(4).cast::<i32>().read_volatile();
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: ElementAt = core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        let mut index = 0;
        while index < count {
            let element = element_at(this, index).read_volatile() as usize as *mut u8;
            if !element.is_null() {
                let element_vtable = element.cast::<u32>().read_volatile() as usize as *const u32;
                let release: ElementRelease = core::mem::transmute(element_vtable.add(1).read_volatile() as usize);
                release(element);
            }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let array = &*this.cast::<HostOpaqueObservableArray>();
        if array.enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < array.count {
            let element = ((*array.vtable).element_at)(this, index).read().element;
            if !element.is_null() {
                ((*(*element.cast::<HostElement>()).vtable).release)(element);
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;
    static mut CELLS: [HostElementCell; 4] = [HostElementCell { element: ptr::null_mut() }; 4];

    unsafe extern "C" fn element_at(_: *mut u8, index: i32) -> *mut HostElementCell {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn release(element: *mut u8) {
        RELEASED[RELEASE_COUNT] = element as usize;
        RELEASE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostOpaqueObservableArrayVtable) -> HostOpaqueObservableArray {
        HostOpaqueObservableArray { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            let array_vtable = HostOpaqueObservableArrayVtable { unresolved_00_3c: [0; 16], element_at };
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            opaque_observable_array_dispose_elements((&mut fixture(0, 2, &array_vtable) as *mut HostOpaqueObservableArray).cast());
            opaque_observable_array_dispose_elements((&mut fixture(1, 0, &array_vtable) as *mut HostOpaqueObservableArray).cast());
            opaque_observable_array_dispose_elements((&mut fixture(1, -1, &array_vtable) as *mut HostOpaqueObservableArray).cast());
            CELLS = [HostElementCell { element: ptr::null_mut() }; 4];
            opaque_observable_array_dispose_elements((&mut fixture(1, 1, &array_vtable) as *mut HostOpaqueObservableArray).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(RELEASE_COUNT, 0);
        }
    }

    #[test]
    fn releases_populated_elements_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let array_vtable = HostOpaqueObservableArrayVtable { unresolved_00_3c: [0; 16], element_at };
            let element_vtable = HostElementVtable { unresolved_00: 0, release };
            let mut first = HostElement { vtable: &element_vtable };
            let mut third = HostElement { vtable: &element_vtable };
            CELLS = [
                HostElementCell { element: ptr::addr_of_mut!(first).cast() },
                HostElementCell { element: ptr::null_mut() },
                HostElementCell { element: ptr::addr_of_mut!(third).cast() },
                HostElementCell { element: ptr::null_mut() },
            ];
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            opaque_observable_array_dispose_elements((&mut fixture(1, 3, &array_vtable) as *mut HostOpaqueObservableArray).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[ptr::addr_of_mut!(first) as usize, ptr::addr_of_mut!(third) as usize]);
        }
    }
}
