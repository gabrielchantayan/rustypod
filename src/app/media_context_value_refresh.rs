//! `media_context_value_refresh` — retailOS `FUN_0817be10`, load 0x0817be10.
//!
//! True extent [0x0817be10,0x0817be60): 80 bytes, next function push at
//! 0x0817be60. Raw A32 decoding verifies one outgoing plain BL, zero
//! predicated BLs, two virtual BLX calls, and a tail B to mutex unlock.
//! Incoming calls: plain BL at 0x0817d398 and BLNE at 0x0817d4ec.
//! Lock the embedded mutex at +0xa4c, then, if the context at +0x54 exists,
//! query its secondary interface at +4 through vtable +0x94 and forward the
//! result to this object's vtable +0x100. Return the unlock status unchanged;
//! the lock status is ignored. Callers use the query in time comparisons,
//! but the virtual methods' concrete identities remain unresolved.
//!
//! Deliberate deviations: use the existing REGION_MUTEX_OPS seam for the
//! raw-verified 0x082621a8/0x082621ac veneers to posix_mutex_lock/unlock.
//! repr(C) pointers and vtable slots widen on hosts, retaining field order
//! rather than target byte offsets. Ghidra's inlined unlock body is excluded.

use crate::heap::block_region::{RegionMutexOps, REGION_MUTEX_OPS};

#[repr(C)]
pub struct MediaValueVtable {
    pub reserved: [usize; 0x100 / 4],
    pub accept_value: unsafe extern "C" fn(*mut MediaValueOwner, u32),
}

#[repr(C)]
pub struct MediaQueryVtable {
    pub reserved: [usize; 0x94 / 4],
    pub query_value: unsafe extern "C" fn(*mut MediaQueryInterface) -> u32,
}

#[repr(C)]
pub struct MediaQueryInterface {
    pub vtable: *const MediaQueryVtable,
}

#[repr(C)]
pub struct MediaValueContext {
    pub primary_vtable: usize,
    pub query_interface: MediaQueryInterface,
}

#[repr(C)]
pub struct MediaValueOwner {
    pub vtable: *const MediaValueVtable,
    pub reserved_04_50: [u32; 20],
    pub context: *mut MediaValueContext,
    pub reserved_58_a48: [u32; (0xa4c - 0x58) / 4],
    pub mutex: [u32; 8],
}

/// # Safety
/// The owner, embedded mutex, optional context and both selected virtual
/// slots must satisfy the unchecked retailOS ABI contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_context_value_refresh(owner: *mut MediaValueOwner) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS));
    refresh_with_mutex(owner, ops)
}

#[inline(always)]
unsafe fn refresh_with_mutex(
    owner: *mut MediaValueOwner,
    ops: RegionMutexOps,
) -> u32 {
    let mutex = core::ptr::addr_of_mut!((*owner).mutex).cast::<u8>();
    (ops.lock)(mutex);
    let context = (*owner).context;
    if !context.is_null() {
        let interface = core::ptr::addr_of_mut!((*context).query_interface);
        let value = ((*(*interface).vtable).query_value)(interface);
        ((*(*owner).vtable).accept_value)(owner, value);
    }
    (ops.unlock)(mutex)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, vec::Vec};

    std::thread_local! { static EVENTS: RefCell<Vec<(u8, usize)>> = RefCell::new(Vec::new()); }
    unsafe extern "C" fn lock(mutex: *mut u8) -> u32 {
        EVENTS.with(|events| events.borrow_mut().push((1, mutex as usize)));
        5 // An error does not suppress either virtual dispatch.
    }
    unsafe extern "C" fn unlock(mutex: *mut u8) -> u32 {
        EVENTS.with(|events| events.borrow_mut().push((4, mutex as usize)));
        0x1a
    }
    unsafe extern "C" fn query(interface: *mut MediaQueryInterface) -> u32 {
        EVENTS.with(|events| events.borrow_mut().push((2, interface as usize)));
        u32::MAX
    }
    unsafe extern "C" fn accept(owner: *mut MediaValueOwner, value: u32) {
        assert_eq!(value, u32::MAX);
        EVENTS.with(|events| events.borrow_mut().push((3, owner as usize)));
        (*owner).reserved_04_50[0] = value;
    }

    #[test]
    fn optional_context_and_full_word_result_preserve_order_and_unlock_status() {
        let query_vtable = MediaQueryVtable { reserved: [0; 0x94 / 4], query_value: query };
        let owner_vtable = MediaValueVtable { reserved: [0; 0x100 / 4], accept_value: accept };
        let mut context = MediaValueContext { primary_vtable: 0, query_interface: MediaQueryInterface { vtable: &query_vtable } };
        let mut owner = MediaValueOwner { vtable: &owner_vtable, reserved_04_50: [0; 20], context: core::ptr::null_mut(), reserved_58_a48: [0; (0xa4c - 0x58) / 4], mutex: [0; 8] };
        let mutex = owner.mutex.as_mut_ptr() as usize;
        for present in [false, true] {
            EVENTS.with(|events| events.borrow_mut().clear());
            owner.context = if present { &mut context } else { core::ptr::null_mut() };
            unsafe { assert_eq!(refresh_with_mutex(&mut owner, RegionMutexOps { lock, unlock }), 0x1a); }
            let expected = if present {
                std::vec![(1, mutex), (2, &mut context.query_interface as *mut _ as usize), (3, &mut owner as *mut _ as usize), (4, mutex)]
            } else { std::vec![(1, mutex), (4, mutex)] };
            EVENTS.with(|events| assert_eq!(*events.borrow(), expected));
            assert_eq!(owner.reserved_04_50[0], if present { u32::MAX } else { 0 });
        }
    }
}
