//! `indexed_release` — original: `FUN_083d200c` @ `0x083d200c` (72 bytes:
//! eighteen ARM words; the next real function starts at `0x083d2054`).
//!
//! Verified call count: three incoming plain `bl`, zero predicated calls; the
//! body makes one direct `bl` to [`crate::heap::veneers::operator_delete`] and
//! one virtual `blx` through vtable slot `+0x40`.
//!
//! # Algorithm
//!
//! If `enabled` (`+0x10`) is clear, return. Otherwise, for each non-negative
//! index below `count` (`+0x04`), call vtable slot `+0x40` with `this` and the
//! index, then delete the pointer in the returned cell.
//!
//! Target objects retain the retail 32-bit word layout. The host-only typed
//! representation deliberately widens the vtable pointer so fixtures can use
//! native function pointers; target code instead reads target-width fields at
//! their verified byte offsets.

use crate::heap::veneers::operator_delete;

/// Host representation of the vtable entry called at target offset `+0x40`.
pub type IndexedReleaseAt = unsafe extern "C" fn(*mut IndexedRelease, i32) -> *mut *mut u8;

/// Host representation of the object vtable.
#[repr(C)]
pub struct IndexedReleaseVtable {
    pub unresolved_00_3c: [usize; 16],
    pub at: IndexedReleaseAt,
}

/// Collection whose indexed elements are individually released.
#[repr(C)]
pub struct IndexedRelease {
    pub vtable: *const IndexedReleaseVtable,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
pub type IndexedReleaseDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_delete(ptr: *mut u8) {
    operator_delete(ptr);
}

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_RELEASE_DELETE: IndexedReleaseDelete = host_delete;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_element(ptr: *mut u8) {
    operator_delete(ptr);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_element(ptr: *mut u8) {
    INDEXED_RELEASE_DELETE(ptr);
}

/// indexed_release — original: `FUN_083d200c` @ `0x083d200c` (72 bytes).
///
/// Releases each indexed element only while the `+0x10` enable byte is set.
/// The original has no NULL checks on `this`, its vtable, the virtual result,
/// or the result cell; callers must uphold those contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_release(this: *mut IndexedRelease) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if base.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = base.add(0x04).cast::<i32>().read_volatile();
        let vtable = base.cast::<u32>().read_volatile() as usize;
        let at: unsafe extern "C" fn(*mut IndexedRelease, i32) -> *mut *mut u8 =
            core::mem::transmute((vtable + 0x40) as *const ());
        let mut index = 0;
        while index < count {
            release_element(at(this, index).read_volatile());
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        if (*this).enabled == 0 {
            return;
        }
        let count = (*this).count;
        let mut index = 0;
        while index < count {
            release_element(((*(*this).vtable).at)(this, index).read_volatile());
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
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [*mut u8; 4] = [core::ptr::null_mut(); 4];

    unsafe extern "C" fn element_at(_: *mut IndexedRelease, index: i32) -> *mut *mut u8 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETED[DELETE_COUNT] = ptr as usize;
        DELETE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32, vtable: *const IndexedReleaseVtable) -> IndexedRelease {
        IndexedRelease { vtable, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_collections() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = IndexedReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            INDEX_COUNT = 0;
            DELETE_COUNT = 0;
            INDEXED_RELEASE_DELETE = record_delete;
            indexed_release(&mut fixture(0, 3, &vtable));
            indexed_release(&mut fixture(1, 0, &vtable));
            indexed_release(&mut fixture(1, -1, &vtable));
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn releases_every_index_in_ascending_order() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = IndexedReleaseVtable { unresolved_00_3c: [0; 16], at: element_at };
            CELLS = [0x1000usize as *mut u8, 0x2000usize as *mut u8, 0x3000usize as *mut u8, core::ptr::null_mut()];
            INDEX_COUNT = 0;
            DELETE_COUNT = 0;
            INDEXED_RELEASE_DELETE = record_delete;
            indexed_release(&mut fixture(1, 3, &vtable));
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x2000, 0x3000]);
        }
    }
}
