//! Shared payload kind selection — retailOS `FUN_08143474` @ `0x08143474`.
//!
//! Raw ARM occupies exactly 160 bytes, `0x08143474..0x08143513`; the pool
//! word at `0x08143514` and a new `push` prologue at `0x08143518` establish
//! the next real function boundary. Complete A32 decoding finds three inbound
//! plain `bl` call sites and zero predicated inbound `bl` forms. The body has
//! six plain outbound `bl` calls and no predicated `bl`: allocate 12 bytes,
//! build an empty secondary shared-cell handle, configure the existing payload,
//! then release and clear the input handle when configuration rejects the kind.
//!
//! Deliberate deviations: the unported configuration routine at `0x081436d0`
//! is an address-based target call; host tests substitute it through
//! `SharedPayloadKindOps`. The literal-vtable allocation is represented as
//! three target-width words even on hosts, preserving its 12-byte request.

use crate::cxx::shared_cell::{shared_cell_construct_secondary, shared_cell_release_secondary, SharedCell};
use crate::heap::veneers::operator_new;

const KIND_STATE_VTABLE: u32 = 0x0898_5d98;
const KIND_STATE_WORDS: usize = 3;
const RETAIL_CONFIGURE_SHARED_PAYLOAD_KIND: usize = 0x0814_36d0;

type ConfigureSharedPayloadKind = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn configure_shared_payload_kind(payload: *mut u8, kind: u32) -> u32 {
    let configure: ConfigureSharedPayloadKind = core::mem::transmute(RETAIL_CONFIGURE_SHARED_PAYLOAD_KIND);
    configure(payload, kind)
}

#[cfg(all(not(target_os = "none"), test))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SharedPayloadKindOps {
    pub configure: ConfigureSharedPayloadKind,
}

#[cfg(all(not(target_os = "none"), test))]
unsafe extern "C" fn accept_shared_payload_kind(_payload: *mut u8, _kind: u32) -> u32 {
    1
}

#[cfg(all(not(target_os = "none"), test))]
pub static mut SHARED_PAYLOAD_KIND_OPS: SharedPayloadKindOps = SharedPayloadKindOps {
    configure: accept_shared_payload_kind,
};

#[cfg(all(not(target_os = "none"), test))]
#[inline(always)]
unsafe fn configure_shared_payload_kind(payload: *mut u8, kind: u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(SHARED_PAYLOAD_KIND_OPS.configure))(payload, kind)
}

/// Selects `kind` for the payload held by `slot`.
///
/// The retail body unconditionally allocates and initializes a 12-byte
/// `{ vtable, -1, 0 }` state object. It then obtains the slot's payload and,
/// if non-NULL, calls the target kind configurator. A zero result releases the
/// input shared cell through its secondary sibling, leaving `slot` empty.
///
/// # Safety
/// `slot` must be a valid shared-cell slot. A non-NULL cell must contain a
/// valid payload pointer, and its reference count must meet
/// `shared_cell_release_secondary`'s contract if the configurator rejects.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_payload_select_kind")]
#[inline(never)]
pub unsafe extern "C" fn shared_payload_select_kind(slot: *mut *mut SharedCell, kind: u32) {
    let state = operator_new(KIND_STATE_WORDS * core::mem::size_of::<u32>()).cast::<u32>();
    core::ptr::write(state, KIND_STATE_VTABLE);
    core::ptr::write(state.add(1), u32::MAX);
    core::ptr::write(state.add(2), 0);

    let cell = *slot;
    let payload = if cell.is_null() { core::ptr::null_mut() } else { (*cell).value as *mut u8 };
    if !payload.is_null() && configure_shared_payload_kind(payload, kind) == 0 {
        let mut empty = core::ptr::null_mut();
        shared_cell_construct_secondary(&mut empty, core::ptr::null_mut());
        if slot != core::ptr::addr_of_mut!(empty) {
            shared_cell_release_secondary(slot);
            *slot = empty;
            if !empty.is_null() {
                (*empty).refcount = (*empty).refcount.wrapping_add(1);
            }
        }
        shared_cell_release_secondary(&mut empty);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut NEXT_ALLOCATION: *mut u8 = core::ptr::null_mut();
    static mut CONFIGURED: (*mut u8, u32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn alloc(_heap: *mut HeapDescriptorDescriptor, _size: usize, _tag: usize) -> *mut u8 {
        core::ptr::read_volatile(core::ptr::addr_of!(NEXT_ALLOCATION))
    }
    unsafe extern "C" fn reject(payload: *mut u8, kind: u32) -> u32 {
        *core::ptr::addr_of_mut!(CONFIGURED) = (payload, kind);
        0
    }
    unsafe extern "C" fn accept(payload: *mut u8, kind: u32) -> u32 {
        *core::ptr::addr_of_mut!(CONFIGURED) = (payload, kind);
        1
    }

    struct Bench { heap: HeapVeneerOps, payload: SharedPayloadKindOps }
    fn bench(allocation: *mut u8, configure: ConfigureSharedPayloadKind) -> Bench {
        while OPS_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { std::thread::yield_now(); }
        unsafe {
            *core::ptr::addr_of_mut!(NEXT_ALLOCATION) = allocation;
            *core::ptr::addr_of_mut!(CONFIGURED) = (core::ptr::null_mut(), 0);
            let heap = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
            let payload = core::ptr::read_volatile(core::ptr::addr_of!(SHARED_PAYLOAD_KIND_OPS));
            core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), HeapVeneerOps { alloc, ..heap });
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SHARED_PAYLOAD_KIND_OPS), SharedPayloadKindOps { configure });
            Bench { heap, payload }
        }
    }
    impl Drop for Bench { fn drop(&mut self) { unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.heap); core::ptr::write_volatile(core::ptr::addr_of_mut!(SHARED_PAYLOAD_KIND_OPS), self.payload); } OPS_LOCK.store(false, Ordering::Release); } }

    #[test]
    fn accepted_payload_is_configured_and_retained() {
        let Some(storage) = try_map_u32_slab(hints::SHARED_PAYLOAD_SELECT_KIND, 0x40) else { return; };
        let _bench = bench(storage.cast(), accept);
        let mut cell = SharedCell { value: 0x1234usize, refcount: 2 };
        let mut slot = core::ptr::addr_of_mut!(cell);
        unsafe { shared_payload_select_kind(&mut slot, 7); }
        assert_eq!(unsafe { CONFIGURED }, (0x1234usize as *mut u8, 7));
        assert_eq!(slot, core::ptr::addr_of_mut!(cell));
        assert_eq!(cell.refcount, 2);
        assert_eq!(unsafe { [storage.cast::<u32>().read(), storage.cast::<u32>().add(1).read(), storage.cast::<u32>().add(2).read()] }, [KIND_STATE_VTABLE, u32::MAX, 0]);
    }

    #[test]
    fn rejected_payload_releases_and_clears_slot() {
        let Some(storage) = try_map_u32_slab(hints::SHARED_PAYLOAD_SELECT_KIND, 0x40) else { return; };
        let _bench = bench(storage.cast(), reject);
        let mut cell = SharedCell { value: 0x5678usize, refcount: 2 };
        let mut slot = core::ptr::addr_of_mut!(cell);
        unsafe { shared_payload_select_kind(&mut slot, 3); }
        assert_eq!(unsafe { CONFIGURED }, (0x5678usize as *mut u8, 3));
        assert!(slot.is_null());
        assert_eq!(cell.refcount, 1);
    }
}
