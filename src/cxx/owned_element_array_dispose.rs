//! `owned_element_array_dispose` — retailOS `FUN_0839c98c` @ `0x0839c98c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the 76-byte body
//! `0x0839c98c..0x0839c9d4`; the next independently entered function begins at
//! `0x0839c9d8`. It has three plain direct `bl` calls — the indexed accessor at
//! `0x083d5fec`, unresolved element stage at `0x0811c15c`, and
//! `operator_delete` at `0x082aad24` — and no predicated `bl` calls. Whole-image
//! decoding finds three inbound plain `bl` sites and no predicated direct callers.
//!
//! ## Algorithm
//!
//! When byte `+0x28` is nonzero, walk signed indices `[0, count)`. The indexed
//! accessor returns a cell whose first word is an owned object. Non-NULL objects
//! go through the still-unidentified direct stage at `0x0811c15c`; its return is
//! passed directly to tag-2 `operator_delete`.
//!
//! Deliberate deviation: the unidentified direct stage remains an explicit
//! address-backed seam. Target builds call its verified retailOS address; host
//! tests replace it, and widen the vtable pointer, because host callback pointers
//! cannot occupy target u32 words.

use crate::heap::veneers::operator_delete;

/// Firmware load address of the direct indexed accessor with no established
/// class identity.
pub const OWNED_ELEMENT_ARRAY_AT_ADDRESS: usize = 0x083d_5fec;

/// Firmware load address of the direct element stage with no established class
/// identity.
pub const OWNED_ELEMENT_ARRAY_DIRECT_STAGE_ADDRESS: usize = 0x0811_c15c;

/// Direct indexed accessor at `0x083d5fec`.
pub type OwnedElementArrayAt = unsafe extern "C" fn(*mut OwnedElementArrayDispose, i32) -> *mut u32;

/// Direct stage at `0x0811c15c`; its returned pointer feeds `operator_delete`.
pub type OwnedElementArrayDirectStage = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Target-layout prefix used by the disposal walk.
#[repr(C)]
pub struct OwnedElementArrayDispose {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_27: [u8; 0x20],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owned_element_array_at(
    this: *mut OwnedElementArrayDispose,
    index: i32,
) -> *mut u32 {
    let at: OwnedElementArrayAt = unsafe { core::mem::transmute(OWNED_ELEMENT_ARRAY_AT_ADDRESS) };
    unsafe { at(this, index) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owned_element_array_at(
    _this: *mut OwnedElementArrayDispose,
    _index: i32,
) -> *mut u32 {
    panic!("owned_element_array_dispose requires unresolved FUN_083d5fec")
}

#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_AT: OwnedElementArrayAt = missing_owned_element_array_at;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owned_element_array_direct_stage(object: *mut u8) -> *mut u8 {
    let direct_stage: OwnedElementArrayDirectStage = unsafe {
        core::mem::transmute(OWNED_ELEMENT_ARRAY_DIRECT_STAGE_ADDRESS)
    };
    unsafe { direct_stage(object) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owned_element_array_direct_stage(_object: *mut u8) -> *mut u8 {
    panic!("owned_element_array_dispose requires unresolved FUN_0811c15c")
}

#[cfg(target_os = "none")]
pub const DEFAULT_OWNED_ELEMENT_ARRAY_DIRECT_STAGE: OwnedElementArrayDirectStage =
    firmware_owned_element_array_direct_stage;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_OWNED_ELEMENT_ARRAY_DIRECT_STAGE: OwnedElementArrayDirectStage =
    missing_owned_element_array_direct_stage;

/// Active direct-call boundary for the unidentified element stage.
pub static mut OWNED_ELEMENT_ARRAY_DIRECT_STAGE: OwnedElementArrayDirectStage =
    DEFAULT_OWNED_ELEMENT_ARRAY_DIRECT_STAGE;

#[inline(always)]
unsafe fn dispose_cell(cell: *mut u32) {
    let object = cell.read_volatile() as usize as *mut u8;
    if object.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    let allocation = unsafe { firmware_owned_element_array_direct_stage(object) };
    #[cfg(not(target_os = "none"))]
    let allocation = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_DIRECT_STAGE))(object)
    };

    #[cfg(target_os = "none")]
    unsafe { operator_delete(allocation) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        // Host fixtures do not have retail heap headers, so the direct stage
        // supplies the observable allocation pointer and the test seam records it.
        OWNED_ELEMENT_ARRAY_DELETE(allocation)
    };
}

#[cfg(not(target_os = "none"))]
pub type OwnedElementArrayDelete = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_DELETE: OwnedElementArrayDelete = operator_delete;

/// Disposes and releases every populated owned element while enabled.
///
/// Original: `FUN_0839c98c` @ `0x0839c98c` (76 bytes; 3 inbound plain `bl`
/// calls, no predicated direct callers).
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Each non-NULL cell word must satisfy the unidentified direct stage and its
/// returned pointer must be accepted by `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_dispose(this: *mut OwnedElementArrayDispose) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x28).read_volatile() } == 0 {
            return;
        }
        let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
        let mut index = 0;
        while index < count {
            unsafe { dispose_cell(firmware_owned_element_array_at(this, index)) };
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostOwnedElementArrayDispose>();
        if unsafe { (*host).enabled } == 0 {
            return;
        }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let at = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_AT)) };
            unsafe { dispose_cell(at(this, index)) };
            index += 1;
        }
    }
}

/// Host-only representation preserving target field offsets.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedElementArrayDispose {
    pub target_vtable: u32,
    pub count: i32,
    pub unresolved_08_27: [u8; 0x20],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut STAGED: [usize; 4] = [0; 4];
    static mut STAGE_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];

    unsafe extern "C" fn element_at(_: *mut OwnedElementArrayDispose, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_stage(object: *mut u8) -> *mut u8 {
        unsafe { STAGED[STAGE_COUNT] = object as usize; STAGE_COUNT += 1; object.sub(8) }
    }

    unsafe extern "C" fn record_delete(allocation: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = allocation as usize; DELETE_COUNT += 1 }
    }

    fn fixture(enabled: u8, count: i32) -> HostOwnedElementArrayDispose {
        HostOwnedElementArrayDispose { target_vtable: 0, count, unresolved_08_27: [0; 0x20], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            OWNED_ELEMENT_ARRAY_AT = element_at;
            INDEX_COUNT = 0; STAGE_COUNT = 0; DELETE_COUNT = 0;
            OWNED_ELEMENT_ARRAY_DIRECT_STAGE = record_stage;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_dispose((&mut fixture(0, 2) as *mut HostOwnedElementArrayDispose).cast());
            owned_element_array_dispose((&mut fixture(1, 0) as *mut HostOwnedElementArrayDispose).cast());
            owned_element_array_dispose((&mut fixture(1, -1) as *mut HostOwnedElementArrayDispose).cast());
            CELLS = [0; 4];
            owned_element_array_dispose((&mut fixture(1, 1) as *mut HostOwnedElementArrayDispose).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(STAGE_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn stages_then_deletes_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            OWNED_ELEMENT_ARRAY_AT = element_at;
            CELLS = [0x1008, 0, 0x3008, 0];
            INDEX_COUNT = 0; STAGE_COUNT = 0; DELETE_COUNT = 0;
            OWNED_ELEMENT_ARRAY_DIRECT_STAGE = record_stage;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete;
            owned_element_array_dispose((&mut fixture(1, 3) as *mut HostOwnedElementArrayDispose).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&STAGED[..STAGE_COUNT], &[0x1008, 0x3008]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
