//! Lazy installation of the OpenSSL ex-data implementation vtable.
//!
//! `FUN_08075914` @ 0x08075914: 72 bytes (68 code, 4 literal), ending
//! at the next real entry 0x0807595c. Raw A32 decoding finds zero incoming
//! plain BLs and two incoming BLEQs (0x080439fc, 0x08043e20). The body has
//! one plain BL, zero predicated BLs, and a tail B to resource_op_dispatch.
//!
//! Acquire resource 2 (op 9), read singleton 0x08a0e9e0 word zero, and
//! install its embedded vtable at +12 only if absent. Preserve any existing
//! implementation. Release resource 2 (op 10) after publication.
//!
//! Deliberate deviations: host storage is an explicit u32-word fixture;
//! its embedded vtable address is supplied separately to avoid truncating
//! native host pointers. Target calls the verified stock resource dispatcher;
//! hosts reuse its ported hook seam. The release tail branch is expressed
//! as a normal returning Rust call.

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ExDataImplementationStorage {
    pub implementation_slot: *mut u32,
    pub embedded_vtable: u32,
}

#[cfg(not(target_os = "none"))]
pub static mut EX_DATA_IMPLEMENTATION_STORAGE: ExDataImplementationStorage = ExDataImplementationStorage {
    implementation_slot: core::ptr::null_mut(),
    embedded_vtable: 0,
};

/// Install the default ex-data implementation only when no override exists.
/// Original: 0x08075914, 72 bytes; two incoming BLEQs, one outgoing BL.
///
/// # Safety
/// The resource dispatcher must be configured for the firmware's locks.
/// Host storage must provide an aligned writable u32 slot and a valid
/// target-width embedded-vtable address. Target requires the fixed singleton.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_ex_data_implementation_ensure() {
    #[cfg(target_os = "none")]
    let dispatch = core::mem::transmute::<usize, unsafe extern "C" fn(u32, i32, u32, u32)>(0x0804_3b94);
    #[cfg(not(target_os = "none"))]
    let dispatch = crate::resource_op::resource_op_dispatch;
    dispatch(9, 2, 0, 0);
    #[cfg(target_os = "none")]
    let (slot, embedded_vtable) = (0x08a0_e9e0 as *mut u32, 0x08a0_e9ec);
    #[cfg(not(target_os = "none"))]
    let (slot, embedded_vtable) = {
        let storage = core::ptr::read_volatile(core::ptr::addr_of!(EX_DATA_IMPLEMENTATION_STORAGE));
        (storage.implementation_slot, storage.embedded_vtable)
    };
    if core::ptr::read_volatile(slot) == 0 {
        core::ptr::write_volatile(slot, embedded_vtable);
    }
    dispatch(10, 2, 0, 0);
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::resource_op::{RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK};
    use std::sync::atomic::{AtomicU32, Ordering};

    static PHASE: AtomicU32 = AtomicU32::new(0);
    static ACQUIRE_VALUE: AtomicU32 = AtomicU32::new(0);
    static RELEASED_VALUE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn dispatch(op: u32, resource: i32, a: u32, b: u32) {
        assert_eq!((resource, a, b), (2, 0, 0));
        let slot = EX_DATA_IMPLEMENTATION_STORAGE.implementation_slot;
        if op == 9 {
            assert_eq!(PHASE.swap(1, Ordering::SeqCst), 0);
            let acquired = ACQUIRE_VALUE.load(Ordering::SeqCst);
            if acquired != 0 {
                *slot = acquired;
            }
        } else {
            assert_eq!(op, 10);
            assert_eq!(PHASE.swap(2, Ordering::SeqCst), 1);
            RELEASED_VALUE.store(*slot, Ordering::SeqCst);
        }
    }

    #[test]
    fn initializes_preserves_overrides_and_observes_acquire_side_publication() {
        let _guard = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        unsafe {
            let saved_hooks = RESOURCE_OP_HOOKS;
            let saved_storage = EX_DATA_IMPLEMENTATION_STORAGE;
            let mut words = [0u32, 0x12345678, 0x87654321, 0xabcdef01];
            EX_DATA_IMPLEMENTATION_STORAGE = ExDataImplementationStorage {
                implementation_slot: words.as_mut_ptr(),
                embedded_vtable: 0x08a0_e9ec,
            };
            RESOURCE_OP_HOOKS.static_op = Some(dispatch);
            for (existing, acquired) in [(0, 0), (0x08123400, 0), (u32::MAX, 0), (0, 0x08234500)] {
                words[0] = existing;
                ACQUIRE_VALUE.store(acquired, Ordering::SeqCst);
                PHASE.store(0, Ordering::SeqCst);
                crypto_ex_data_implementation_ensure();
                let expected = if acquired != 0 { acquired } else if existing != 0 { existing } else { 0x08a0_e9ec };
                assert_eq!(words, [expected, 0x12345678, 0x87654321, 0xabcdef01]);
                assert_eq!(RELEASED_VALUE.load(Ordering::SeqCst), expected);
                assert_eq!(PHASE.load(Ordering::SeqCst), 2);
            }
            RESOURCE_OP_HOOKS = saved_hooks;
            EX_DATA_IMPLEMENTATION_STORAGE = saved_storage;
        }
    }
}
