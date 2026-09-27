//! Dispose parser diagnostics held by an opaque observable array.
//!
//! `opaque_observable_array_parse_diagnostics_cleanup` — retailOS
//! `FUN_083d0fbc` @ **0x083d0fbc**.
//!
//! ## Verified extent and calls
//! Raw `osos.dec` establishes the exact **88-byte** body,
//! `0x083d0fbc..0x083d1013`: twenty-two A32 words from `push {r4,r5,r6,lr}`
//! through `pop {r4,r5,r6,pc}`. `0x083d1014` begins the next independently
//! entered function. The body has two unconditional plain direct `bl` calls,
//! to `parse_diagnostic_destroy` at `0x0826fd10` and `operator_delete` at
//! `0x082aad24`, no predicated direct `bl` calls, and one unconditional
//! indirect `blx` through array vtable slot `+0x40`. Whole-image decoding finds
//! two inbound unconditional plain `bl` sites (`0x083d106c`, `0x083d108c`) and
//! no predicated inbound `bl` sites.
//!
//! ## Algorithm
//!
//! If enabled byte `+0x10` is nonzero, visit signed indices `[0, count)`. The
//! array's slot-`+0x40` cell lookup yields a cell whose first word optionally
//! points to a parser diagnostic. Every non-NULL diagnostic is destroyed, then
//! its returned allocation body is passed to `operator_delete`.
//!
//! ## Deliberate deviations
//!
//! RetailOS vtable entries and object pointers are 32-bit words. Target builds
//! load those words at their observed offsets; host tests use native pointers
//! and callbacks. The direct callees are already ported and called directly on
//! target; host tests replace only those effects with recording operations.

#[cfg(target_os = "none")]
use crate::app::parse_diagnostic::{parse_diagnostic_destroy, ParseDiagnostic};
#[cfg(target_os = "none")]
use crate::heap::veneers::operator_delete;

const COUNT_OFFSET: usize = 0x04;
const ENABLED_OFFSET: usize = 0x10;
const CELL_AT_SLOT: usize = 0x40 / 4;

#[cfg(not(target_os = "none"))]
pub type HostCellAt = unsafe extern "C" fn(*mut HostOpaqueObservableArray, i32) -> *mut HostDiagnosticCell;
#[cfg(not(target_os = "none"))]
pub type HostDiagnosticDestroy = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type HostDelete = unsafe extern "C" fn(*mut u8);

/// Host representation of the array's recovered vtable slot `+0x40`.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArrayVtable {
    pub _slots_before_cell_at: [usize; CELL_AT_SLOT],
    pub cell_at: HostCellAt,
}

/// Host representation of the target fields this cleanup reads.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOpaqueObservableArray {
    pub vtable: *const HostOpaqueObservableArrayVtable,
    pub count: i32,
    pub _unknown_08: u32,
    pub _unknown_0c: u32,
    pub enabled: u8,
}

/// Host representation of a cell whose first target word is a diagnostic.
#[derive(Clone, Copy)]
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDiagnosticCell {
    pub diagnostic: *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut u8) -> *mut u8 {
    panic!("host tests must replace OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_: *mut u8) {
    panic!("host tests must replace OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS")
}

/// Host-only replacements for the two direct callee effects.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS: (HostDiagnosticDestroy, HostDelete) =
    (missing_destroy, missing_delete);

/// Disposes every populated parser diagnostic while the array is enabled.
///
/// # Safety
///
/// `array` must be a readable opaque observable array. When enabled, its
/// vtable slot `+0x40` must accept each signed index below `count` and return
/// a readable cell. Every non-NULL first cell word must be a valid parser
/// diagnostic allocation accepted by its destructor and `operator_delete`.
#[cfg(target_os = "none")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_parse_diagnostics_cleanup(array: *mut u8) {
    if core::ptr::read_volatile(array.add(ENABLED_OFFSET)) == 0 {
        return;
    }
    let count = core::ptr::read_volatile(array.add(COUNT_OFFSET).cast::<i32>());
    let mut index = 0;
    loop {
        if index >= count {
            return;
        }
        let vtable = core::ptr::read_volatile(array.cast::<u32>()) as usize as *const u32;
        let cell_at: unsafe extern "C" fn(*mut u8, i32) -> *mut u32 =
            core::mem::transmute(core::ptr::read_volatile(vtable.add(CELL_AT_SLOT)) as usize);
        let diagnostic = core::ptr::read_volatile(cell_at(array, index));
        if diagnostic != 0 {
            operator_delete(parse_diagnostic_destroy((diagnostic as usize as *mut u8).cast::<ParseDiagnostic>()).cast());
        }
        index += 1;
    }
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_parse_diagnostics_cleanup(array: *mut u8) {
    let array = array.cast::<HostOpaqueObservableArray>();
    if (*array).enabled == 0 {
        return;
    }
    let cell_at = (*(*array).vtable).cell_at;
    for index in 0..(*array).count {
        let diagnostic = (*cell_at(array, index)).diagnostic;
        if !diagnostic.is_null() {
            let (destroy, delete) = OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS;
            delete(destroy(diagnostic));
        }
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;
    extern crate std;
    use super::*;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut INDICES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut DESTROYED: [usize; 4] = [0; 4];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [HostDiagnosticCell; 3] = [HostDiagnosticCell { diagnostic: core::ptr::null_mut() }; 3];

    unsafe extern "C" fn cell_at(_: *mut HostOpaqueObservableArray, index: i32) -> *mut HostDiagnosticCell {
        INDICES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }
    unsafe extern "C" fn destroy(diagnostic: *mut u8) -> *mut u8 {
        DESTROYED[DESTROY_COUNT] = diagnostic as usize;
        DESTROY_COUNT += 1;
        diagnostic.wrapping_add(4)
    }
    unsafe extern "C" fn delete(allocation_body: *mut u8) {
        DELETED[DELETE_COUNT] = allocation_body as usize;
        DELETE_COUNT += 1;
    }

    #[test]
    fn skips_disabled_and_nonpositive_arrays_then_disposes_non_null_cells_in_order() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            INDEX_COUNT = 0;
            DESTROY_COUNT = 0;
            DELETE_COUNT = 0;
            CELLS = [
                HostDiagnosticCell { diagnostic: 0x1000usize as *mut u8 },
                HostDiagnosticCell { diagnostic: core::ptr::null_mut() },
                HostDiagnosticCell { diagnostic: 0x3000usize as *mut u8 },
            ];
            OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS = (destroy, delete);
            let vtable = HostOpaqueObservableArrayVtable { _slots_before_cell_at: [0; CELL_AT_SLOT], cell_at };
            let mut array = HostOpaqueObservableArray { vtable: &vtable, count: 3, _unknown_08: 0, _unknown_0c: 0, enabled: 0 };
            opaque_observable_array_parse_diagnostics_cleanup((&mut array as *mut HostOpaqueObservableArray).cast());
            assert_eq!(INDEX_COUNT, 0);
            array.enabled = 1;
            opaque_observable_array_parse_diagnostics_cleanup((&mut array as *mut HostOpaqueObservableArray).cast());
            assert_eq!(&INDICES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[0x1000, 0x3000]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1004, 0x3004]);
            array.count = -1;
            opaque_observable_array_parse_diagnostics_cleanup((&mut array as *mut HostOpaqueObservableArray).cast());
            assert_eq!(INDEX_COUNT, 3);
            OPAQUE_OBSERVABLE_ARRAY_PARSE_DIAGNOSTICS_CLEANUP_OPS = (missing_destroy, missing_delete);
        }
    }
}
