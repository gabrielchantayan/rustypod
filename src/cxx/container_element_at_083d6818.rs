//! Container element accessor.
//!
//! `container_element_at_083d6818` — original: `FUN_083d6818` @
//! **0x083d6818** (24 bytes; true extent `0x083d6818..0x083d6830`, with the
//! next real function beginning at `0x083d6830`). Raw ARM decoding finds two
//! direct incoming calls, both unconditional plain `bl` (at `0x080fe7a0` and
//! `0x083cfd6c`); there are no predicated direct `bl` calls. The body loads the
//! container's vtable, invokes slot `+0x40` as `(container, index) -> void **`,
//! then returns the pointer stored in that element slot.
//!
//! The slot's concrete target is runtime data and has no recovered static
//! identity. Deliberate deviation: host fixtures use a widened native-pointer
//! vtable representation; target builds load the original 32-bit object and
//! vtable words before the indirect call.

type ElementSlotMethod = unsafe extern "C" fn(*mut u8, u32) -> *mut *mut u8;

const VTABLE_ELEMENT_SLOT: usize = 0x40 / 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_element_slot(container: *mut u8, index: u32) -> *mut *mut u8 {
    let vtable = container.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ElementSlotMethod = core::mem::transmute(vtable.add(VTABLE_ELEMENT_SLOT).read_volatile() as usize);
    method(container, index)
}

/// Host representation of the observed vtable slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElementVtable {
    pub unresolved_00_to_3c: [usize; VTABLE_ELEMENT_SLOT],
    pub element_slot: ElementSlotMethod,
}

/// Host representation of a container whose first word is its vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostElementContainer {
    pub vtable: *const HostElementVtable,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_element_slot(container: *mut u8, index: u32) -> *mut *mut u8 {
    let host_container = &*container.cast::<HostElementContainer>();
    ((*host_container.vtable).element_slot)(container, index)
}

/// Returns the pointer stored in the element slot obtained from vtable slot `+0x40`.
///
/// # Safety
///
/// `container`, its vtable slot, and the element slot returned by that method
/// must be valid. retailOS performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn container_element_at_083d6818(container: *mut u8, index: u32) -> *mut u8 {
    dispatch_element_slot(container, index).read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVER: *mut u8 = ptr::null_mut();
    static mut INDEX: u32 = 0;
    static mut SLOTS: [*mut u8; 2] = [ptr::null_mut(); 2];

    unsafe extern "C" fn record_element_slot(container: *mut u8, index: u32) -> *mut *mut u8 {
        RECEIVER = container;
        INDEX = index;
        SLOTS.as_mut_ptr().add(index as usize)
    }

    fn fixture() -> (HostElementContainer, HostElementVtable) {
        (
            HostElementContainer { vtable: ptr::null() },
            HostElementVtable {
                unresolved_00_to_3c: [0; VTABLE_ELEMENT_SLOT],
                element_slot: record_element_slot,
            },
        )
    }

    #[test]
    fn dispatches_slot_40_with_container_and_index_then_loads_the_element_pointer() {
        let _guard = TEST_LOCK.lock();
        let (mut container, vtable) = fixture();
        container.vtable = &vtable;
        let mut first = 0u8;
        let mut second = 0u8;
        unsafe {
            RECEIVER = ptr::null_mut();
            INDEX = u32::MAX;
            SLOTS = [ptr::addr_of_mut!(first), ptr::addr_of_mut!(second)];
            let container_ptr = ptr::addr_of_mut!(container).cast::<u8>();
            assert_eq!(container_element_at_083d6818(container_ptr, 1), ptr::addr_of_mut!(second));
            assert_eq!(RECEIVER, container_ptr);
            assert_eq!(INDEX, 1);
        }
    }

    #[test]
    fn reloads_the_pointer_from_the_returned_slot() {
        let _guard = TEST_LOCK.lock();
        let (mut container, vtable) = fixture();
        container.vtable = &vtable;
        let mut first = 0u8;
        let mut replacement = 0u8;
        unsafe {
            SLOTS = [ptr::addr_of_mut!(first), ptr::null_mut()];
            let container_ptr = ptr::addr_of_mut!(container).cast::<u8>();
            assert_eq!(container_element_at_083d6818(container_ptr, 0), ptr::addr_of_mut!(first));
            SLOTS[0] = ptr::addr_of_mut!(replacement);
            assert_eq!(container_element_at_083d6818(container_ptr, 0), ptr::addr_of_mut!(replacement));
        }
    }
}
