//! `container_dispose_elements` — retailOS `FUN_0839bdb4` @ `0x0839bdb4`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains 19 ARM words from `push {r4,r5,r6,lr}` at
//! `0x0839bdb4` through `pop {r4,r5,r6,pc}` at `0x0839bdfc`; `0x0839be00`
//! starts the next independently entered function, so the true size is **76
//! bytes**. The body has one unconditional virtual `blx` through the container
//! vtable slot `+0x40` and one predicated `blxne` through each non-NULL
//! element's vtable slot `+0x04`. Whole-image ARM branch decoding finds three
//! inbound plain `bl` calls (`0x081b1338`, `0x0839be4c`, and `0x0839be70`) and
//! no predicated direct `bl` calls.
//!
//! ## Algorithm
//!
//! If the byte at `this + 0x28` is nonzero, walk signed indexes `[0, count)`,
//! where `count` is the target word at `+0x04`. The container vtable's `+0x40`
//! accessor yields an element cell. For each non-NULL cell word, invoke that
//! object's vtable slot `+0x04` with the object in `r0`.
//!
//! Deliberate deviation: host fixtures use native-width pointers and callbacks
//! instead of target u32 vtable words. Target builds retain target-width
//! volatile reads and the observed virtual dispatches.

#[cfg(target_os = "none")]
type ElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u32;
#[cfg(target_os = "none")]
type ElementDispose = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub type HostElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut HostElementCell;
#[cfg(not(target_os = "none"))]
pub type HostElementDispose = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContainerDisposeElementsVtable {
    pub unresolved_00_3c: [usize; 16],
    pub element_at: HostElementAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContainerDisposeElements {
    pub vtable: *const HostContainerDisposeElementsVtable,
    pub count: i32,
    pub unresolved_08_27: [u8; 0x20],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HostElementCell {
    pub element: *mut HostElement,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElement {
    pub vtable: *const HostElementVtable,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElementVtable {
    pub unresolved_00: usize,
    pub dispose: HostElementDispose,
}

#[inline(always)]
unsafe fn dispose_element(cell: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let element = cell.read_volatile() as usize as *mut u8;
        if !element.is_null() {
            let vtable = element.cast::<u32>().read_volatile() as usize as *const u32;
            let dispose: ElementDispose = core::mem::transmute(vtable.add(1).read_volatile() as usize);
            dispose(element);
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let element = (cell as *mut HostElementCell).read().element;
        if !element.is_null() {
            ((*element).vtable.read().dispose)(element.cast());
        }
    }
}

/// Disposes populated container elements while the target-layout enable byte is set.
///
/// # Safety
/// `this` must point to a readable container. When enabled, its vtable `+0x40`
/// accessor must return a readable cell for every signed index below `count`.
/// Each non-NULL element must have a callable vtable slot `+0x04`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_dispose_elements(this: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if this.add(0x28).read_volatile() == 0 {
            return;
        }
        let count = this.add(4).cast::<i32>().read_volatile();
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: ElementAt = core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        let mut index = 0;
        while index < count {
            dispose_element(element_at(this, index));
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostContainerDisposeElements>();
        if (*host).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*host).count {
            let cell = ((*(*host).vtable).element_at)(this, index);
            dispose_element(cell.cast());
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
    static mut DISPOSED: [usize; 4] = [0; 4];
    static mut DISPOSE_COUNT: usize = 0;
    static mut CELLS: [HostElementCell; 4] = [HostElementCell { element: core::ptr::null_mut() }; 4];

    unsafe extern "C" fn element_at(_: *mut u8, index: i32) -> *mut HostElementCell {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn record_dispose(element: *mut u8) {
        DISPOSED[DISPOSE_COUNT] = element as usize;
        DISPOSE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostContainerDisposeElementsVtable) -> HostContainerDisposeElements {
        HostContainerDisposeElements { vtable, count, unresolved_08_27: [0; 0x20], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_null_elements() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = HostContainerDisposeElementsVtable { unresolved_00_3c: [0; 16], element_at };
            INDEX_COUNT = 0;
            DISPOSE_COUNT = 0;
            container_dispose_elements((&mut fixture(0, 2, &vtable) as *mut HostContainerDisposeElements).cast());
            container_dispose_elements((&mut fixture(1, 0, &vtable) as *mut HostContainerDisposeElements).cast());
            container_dispose_elements((&mut fixture(1, -1, &vtable) as *mut HostContainerDisposeElements).cast());
            CELLS = [HostElementCell { element: core::ptr::null_mut() }; 4];
            container_dispose_elements((&mut fixture(1, 1, &vtable) as *mut HostContainerDisposeElements).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(DISPOSE_COUNT, 0);
        }
    }

    #[test]
    fn disposes_nonnull_elements_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let container_vtable = HostContainerDisposeElementsVtable { unresolved_00_3c: [0; 16], element_at };
            let element_vtable = HostElementVtable { unresolved_00: 0, dispose: record_dispose };
            let mut first = HostElement { vtable: &element_vtable };
            let mut third = HostElement { vtable: &element_vtable };
            CELLS = [
                HostElementCell { element: &mut first },
                HostElementCell { element: core::ptr::null_mut() },
                HostElementCell { element: &mut third },
                HostElementCell { element: core::ptr::null_mut() },
            ];
            INDEX_COUNT = 0;
            DISPOSE_COUNT = 0;
            container_dispose_elements((&mut fixture(1, 3, &container_vtable) as *mut HostContainerDisposeElements).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DISPOSED[..DISPOSE_COUNT], &[&mut first as *mut HostElement as usize, &mut third as *mut HostElement as usize]);
        }
    }
}
