//! `destroy_derived_state` — retailOS `FUN_0839c7d4` @ `0x0839c7d4`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` contains 22 ARM words from `push {r4,r5,r6,lr}` at
//! `0x0839c7d4` through `pop {r4,r5,r6,pc}` at `0x0839c828`; the next
//! independently entered function starts at `0x0839c82c`, so the true size is
//! **88 bytes**. The body has two plain direct `bl` calls — the unidentified
//! derived-state destructor at `0x08284a88` and `operator_delete` at
//! `0x082aad24` — no predicated direct `bl` calls, and one virtual `blx` through
//! vtable slot `+0x40`. Whole-image A32 decoding finds two inbound plain `bl`
//! calls (`0x0839c878`, `0x0839c89c`) and no predicated direct callers.
//!
//! ## Algorithm
//!
//! If byte `+0x28` is set, walk signed indices `[0, count)` through vtable slot
//! `+0x40`. Each returned cell supplies an optional derived-state allocation in
//! its first word. Destroy and tag-2-delete every non-NULL allocation.
//!
//! ## Deliberate deviations
//!
//! The destructor at `0x08284a88` has no established class identity, so it is an
//! address-backed seam: target builds call its verified retailOS address and
//! host tests replace it. Host vtables use native-width callback pointers;
//! target code reads the verified 32-bit words at retail offsets.

use crate::heap::veneers::operator_delete;

pub const DERIVED_STATE_DESTRUCT_ADDRESS: usize = 0x0828_4a88;
const ELEMENT_AT_SLOT: usize = 0x40 / 4;

type ElementAt = unsafe extern "C" fn(*mut DestroyDerivedState, i32) -> *mut u32;
pub type DerivedStateDestruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[repr(C)]
pub struct DestroyDerivedState {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_27: [u8; 0x20],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_derived_state_destruct(state: *mut u8) -> *mut u8 {
    let destruct: DerivedStateDestruct = unsafe { core::mem::transmute(DERIVED_STATE_DESTRUCT_ADDRESS) };
    unsafe { destruct(state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_derived_state_destruct(_state: *mut u8) -> *mut u8 {
    panic!("destroy_derived_state requires unresolved FUN_08284a88")
}

#[cfg(target_os = "none")]
pub const DEFAULT_DERIVED_STATE_DESTRUCT: DerivedStateDestruct = firmware_derived_state_destruct;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DERIVED_STATE_DESTRUCT: DerivedStateDestruct = missing_derived_state_destruct;

/// Active direct-call boundary for the unidentified destructor at `0x08284a88`.
pub static mut DERIVED_STATE_DESTRUCT: DerivedStateDestruct = DEFAULT_DERIVED_STATE_DESTRUCT;

#[cfg(target_os = "none")]
unsafe fn destroy_and_delete(state: *mut u8) {
    let allocation = unsafe { firmware_derived_state_destruct(state) };
    unsafe { operator_delete(allocation) };
}

#[cfg(not(target_os = "none"))]
pub type DerivedStateDelete = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub static mut DERIVED_STATE_DELETE: DerivedStateDelete = operator_delete;

#[cfg(not(target_os = "none"))]
unsafe fn destroy_and_delete(state: *mut u8) {
    let destruct = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DERIVED_STATE_DESTRUCT)) };
    let allocation = unsafe { destruct(state) };
    let delete = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DERIVED_STATE_DELETE)) };
    unsafe { delete(allocation) };
}

/// Destroys and releases all populated derived-state cells while enabled.
///
/// # Safety
///
/// `this` must address a readable target-layout collection. When enabled, its
/// vtable slot `+0x40` must accept `(this, index)` and return a readable cell.
/// Every non-NULL cell word must be accepted by the derived-state destructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_derived_state(this: *mut DestroyDerivedState) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if unsafe { base.add(0x28).read_volatile() } == 0 { return; }
        let count = unsafe { base.add(4).cast::<i32>().read_volatile() };
        let vtable = unsafe { base.cast::<u32>().read_volatile() as usize as *const u32 };
        let element_at: ElementAt = unsafe { core::mem::transmute(vtable.add(ELEMENT_AT_SLOT).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            let cell = unsafe { element_at(this, index) };
            let state = unsafe { cell.read_volatile() as usize as *mut u8 };
            if !state.is_null() { unsafe { destroy_and_delete(state) }; }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostDestroyDerivedState>();
        if unsafe { (*host).enabled } == 0 { return; }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let element_at = unsafe { (*(*host).vtable).element_at };
            let cell = unsafe { element_at(this, index) };
            let state = unsafe { cell.read() as usize as *mut u8 };
            if !state.is_null() { unsafe { destroy_and_delete(state) }; }
            index += 1;
        }
    }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDestroyDerivedStateVtable {
    pub unresolved_00_3c: [usize; ELEMENT_AT_SLOT],
    pub element_at: ElementAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDestroyDerivedState {
    pub vtable: *const HostDestroyDerivedStateVtable,
    pub count: i32,
    pub unresolved_0c_27: [u8; 0x1c],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];
    static mut DESTROYED: [usize; 4] = [0; 4];
    static mut DESTROY_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn element_at(_: *mut DestroyDerivedState, index: i32) -> *mut u32 {
        unsafe { INDEXES[INDEX_COUNT] = index; INDEX_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }

    unsafe extern "C" fn record_destruct(state: *mut u8) -> *mut u8 {
        unsafe { DESTROYED[DESTROY_COUNT] = state as usize; DESTROY_COUNT += 1; state }
    }

    unsafe extern "C" fn record_delete(allocation: *mut u8) {
        unsafe { DELETED[DELETE_COUNT] = allocation as usize; DELETE_COUNT += 1 }
    }

    fn fixture(enabled: u8, count: i32, vtable: *const HostDestroyDerivedStateVtable) -> HostDestroyDerivedState {
        HostDestroyDerivedState { vtable, count, unresolved_0c_27: [0; 0x1c], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        let vtable = HostDestroyDerivedStateVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        unsafe {
            DERIVED_STATE_DESTRUCT = record_destruct; DERIVED_STATE_DELETE = record_delete;
            INDEX_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0; CELLS = [0; 4];
            destroy_derived_state((&mut fixture(0, 2, &vtable) as *mut HostDestroyDerivedState).cast());
            destroy_derived_state((&mut fixture(1, 0, &vtable) as *mut HostDestroyDerivedState).cast());
            destroy_derived_state((&mut fixture(1, -1, &vtable) as *mut HostDestroyDerivedState).cast());
            destroy_derived_state((&mut fixture(1, 1, &vtable) as *mut HostDestroyDerivedState).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(DESTROY_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn destroys_populated_cells_in_index_order() {
        let _lock = LOCK.lock();
        let vtable = HostDestroyDerivedStateVtable { unresolved_00_3c: [0; ELEMENT_AT_SLOT], element_at };
        unsafe {
            DERIVED_STATE_DESTRUCT = record_destruct; DERIVED_STATE_DELETE = record_delete;
            INDEX_COUNT = 0; DESTROY_COUNT = 0; DELETE_COUNT = 0; CELLS = [0x1000, 0, 0x3000, 0];
            destroy_derived_state((&mut fixture(1, 3, &vtable) as *mut HostDestroyDerivedState).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&DESTROYED[..DESTROY_COUNT], &[0x1000, 0x3000]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000, 0x3000]);
        }
    }
}
