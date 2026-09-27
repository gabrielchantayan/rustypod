//! `observable_array_release_elements_083d119c` — retailOS `FUN_083d119c` @ `0x083d119c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains 22 A32 words from `0x083d119c` through
//! `0x083d11f0`; `0x083d11f4` begins the next independently entered function,
//! so the true size is **88 bytes**. The body has no direct `bl`: one
//! unconditional indirect `blx` through the array vtable slot `+0x40`, and one
//! predicated `blxne` through a non-NULL element's vtable slot `+0x04`.
//! Whole-image branch decoding finds two inbound plain `bl` calls
//! (`0x083d124c` and `0x083d12c4`) and no predicated direct `bl` calls.
//!
//! ## Algorithm
//!
//! If the byte at `this + 0x10` is nonzero, walk signed indices `[0, count)`.
//! The array's `+0x40` virtual accessor returns a cell. If that cell's first
//! word is non-NULL, call the object's vtable slot `+0x04`, passing the object
//! in `r0`.
//!
//! Deliberate deviation: the virtual targets have no established identities.
//! Target builds dispatch through their verified slots; host builds use native
//! vtable fixtures because firmware u32 vtable words cannot hold x86-64
//! callbacks. Target builds also use an empty inline-assembly barrier to retain
//! this distinct retailOS BL target rather than allowing LLVM to fold it into
//! the byte-identical `indexed_element_array_release` at `0x083d00a0`.

/// Target-layout prefix read by the release walk.
#[repr(C)]
pub struct ObservableArrayReleaseElements083d119c {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

/// ABI of the array vtable's indexed accessor at slot `+0x40`.
pub type ObservableArrayReleaseElements083d119cAt = unsafe extern "C" fn(*mut ObservableArrayReleaseElements083d119c, i32) -> *mut u32;

/// ABI of the element vtable method at slot `+0x04`.
pub type ObservableArrayReleaseElements083d119cRelease = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct ObservableArrayReleaseElements083d119cVtable {
    pub unresolved_00_3c: [usize; 16],
    pub at: ObservableArrayReleaseElements083d119cAt,
}

#[inline(always)]
unsafe fn release_element(cell: *mut u32) {
    let object = unsafe { cell.read_volatile() as usize as *mut u8 };
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
        let release: ObservableArrayReleaseElements083d119cRelease = unsafe { core::mem::transmute(vtable.add(0x04 / 4).read_volatile() as usize) };
        unsafe { release(object) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { (OBSERVABLE_ARRAY_RELEASE_ELEMENTS_083D119C_OPS.release)(object) };
}

#[cfg(not(target_os = "none"))]
pub struct ObservableArrayReleaseElements083d119cOps {
    pub release: ObservableArrayReleaseElements083d119cRelease,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_object: *mut u8) {
    panic!("install observable array release-elements host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_RELEASE_ELEMENTS_083D119C_OPS: ObservableArrayReleaseElements083d119cOps = ObservableArrayReleaseElements083d119cOps {
    release: missing_release,
};

/// Releases each populated element returned by the array's indexed accessor.
///
/// # Safety
///
/// `this` must address a readable target-layout array. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Every non-NULL cell word must identify an object whose vtable slot `+0x04`
/// is callable with that object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observable_array_release_elements_083d119c(this: *mut ObservableArrayReleaseElements083d119c) {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x10).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(0x04).cast::<i32>().read_volatile() };
        let vtable = unsafe { base.cast::<u32>().read_volatile() as usize as *const u32 };
        let at: ObservableArrayReleaseElements083d119cAt = unsafe { core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            unsafe { release_element(at(this, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostObservableArrayReleaseElements083d119c>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let cell = unsafe { ((*(*host).vtable).at)(this, index) };
            unsafe { release_element(cell) };
            index += 1;
        }
    }
}

/// Host-only replacement of the target's first word with a native vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostObservableArrayReleaseElements083d119c {
    pub vtable: *const ObservableArrayReleaseElements083d119cVtable,
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
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn element_at(_: *mut ObservableArrayReleaseElements083d119c, index: i32) -> *mut u32 {
        unsafe {
            INDEXES[INDEX_COUNT] = index;
            INDEX_COUNT += 1;
            CELLS.as_mut_ptr().add(index as usize)
        }
    }

    unsafe extern "C" fn record_release(object: *mut u8) {
        unsafe {
            RELEASED[RELEASE_COUNT] = object as usize;
            RELEASE_COUNT += 1;
        }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const ObservableArrayReleaseElements083d119cVtable) -> HostObservableArrayReleaseElements083d119c {
        HostObservableArrayReleaseElements083d119c { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseElements083d119cVtable { unresolved_00_3c: [0; 16], at: element_at };
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            OBSERVABLE_ARRAY_RELEASE_ELEMENTS_083D119C_OPS = ObservableArrayReleaseElements083d119cOps { release: record_release };
            observable_array_release_elements_083d119c((&mut fixture(0, 2, &vtable) as *mut HostObservableArrayReleaseElements083d119c).cast());
            observable_array_release_elements_083d119c((&mut fixture(1, 0, &vtable) as *mut HostObservableArrayReleaseElements083d119c).cast());
            observable_array_release_elements_083d119c((&mut fixture(1, -1, &vtable) as *mut HostObservableArrayReleaseElements083d119c).cast());
            CELLS = [0; 4];
            observable_array_release_elements_083d119c((&mut fixture(1, 1, &vtable) as *mut HostObservableArrayReleaseElements083d119c).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(RELEASE_COUNT, 0);
        }
    }

    #[test]
    fn releases_nonnull_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = ObservableArrayReleaseElements083d119cVtable { unresolved_00_3c: [0; 16], at: element_at };
            CELLS = [0x1000, 0, 0x3000, 0];
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            OBSERVABLE_ARRAY_RELEASE_ELEMENTS_083D119C_OPS = ObservableArrayReleaseElements083d119cOps { release: record_release };
            observable_array_release_elements_083d119c((&mut fixture(1, 3, &vtable) as *mut HostObservableArrayReleaseElements083d119c).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
