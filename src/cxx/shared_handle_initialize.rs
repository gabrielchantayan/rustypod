//! Initializes a slot with the process-wide shared handle.
//!
//! ## Original: `FUN_082a8b68` @ 0x082a8b68 (52 bytes)
//!
//! The raw extent is thirteen ARM words from 0x082a8b68 through the literal
//! pointer at 0x082a8b9c; the distinct release sibling begins at 0x082a8ba0.
//! Decoding every ARM B/BL immediate in `osos.dec` finds seven inbound direct
//! calls, all unconditional `bl` (0x08266e2c, 0x082a94a4, 0x083d97f4,
//! 0x083d9db0, 0x083dad20, 0x083daf1c, and 0x083e78c0), with no predicated
//! forms or direct tail branches. Its sole outbound call is the predicated
//! `bleq 0x082a89e0`, taken only when the shared-object global is NULL.
//!
//! It loads the target-global shared object, invokes its lazy initializer when
//! necessary, reloads that global, stores the object address in `slot`, and
//! increments the object's word-seven (+0x1c) intrusive reference count with
//! 32-bit wrapping arithmetic. The firmware has no NULL guard after the lazy
//! initializer. Host builds replace the target global and unported lazy
//! initializer with test seams; that is the only deliberate deviation.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_SHARED_HANDLE_GLOBAL: *const u32 = 0x08a0_fbdc as *const u32;
const RETAIL_SHARED_HANDLE_BOOTSTRAP: usize = 0x082a_89e0;
const SHARED_HANDLE_REFCOUNT_WORD: usize = 7;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_handle_global() -> u32 {
    core::ptr::read_volatile(RETAIL_SHARED_HANDLE_GLOBAL)
}

#[cfg(not(target_os = "none"))]
pub static mut SHARED_HANDLE_GLOBAL: u32 = 0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_handle_global() -> u32 {
    core::ptr::read_volatile(addr_of!(SHARED_HANDLE_GLOBAL))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn bootstrap_shared_handle() {
    let bootstrap: unsafe extern "C" fn() = core::mem::transmute(RETAIL_SHARED_HANDLE_BOOTSTRAP);
    bootstrap();
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unported_shared_handle_bootstrap() {}

/// Host-side replacement for unported `FUN_082a89e0`.
#[cfg(not(target_os = "none"))]
pub static mut SHARED_HANDLE_BOOTSTRAP: unsafe extern "C" fn() = unported_shared_handle_bootstrap;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn bootstrap_shared_handle() {
    let bootstrap = core::ptr::read_volatile(addr_of!(SHARED_HANDLE_BOOTSTRAP));
    bootstrap();
}

#[cfg(test)]
pub static SHARED_HANDLE_INITIALIZE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// `shared_handle_initialize` — retailOS `FUN_082a8b68` @ `0x082a8b68` (52
/// bytes; seven incoming direct `bl` call sites, all unconditional; zero
/// predicated forms and zero direct tail branches, verified by decoding every
/// ARM B/BL word in `osos.dec`).
///
/// Stores the global shared object in `slot` and increments its +0x1c
/// intrusive reference count. A NULL global first calls the unported lazy
/// bootstrap at `0x082a89e0`, then reloads it. The bootstrap must leave a
/// non-NULL, writable object because the original immediately dereferences it.
///
/// # Safety
/// `slot` must be a valid, aligned writable target-pointer word. The global
/// shared object (or the one installed by the bootstrap) must be valid and
/// writable through word seven.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_handle_initialize(slot: *mut u32) -> *mut u32 {
    if shared_handle_global() == 0 {
        bootstrap_shared_handle();
    }

    let object = shared_handle_global();
    slot.write(object);
    let refcount = (object as usize as *mut u32).add(SHARED_HANDLE_REFCOUNT_WORD);
    refcount.write(refcount.read().wrapping_add(1));
    slot
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::LazyLock;

    const OBJECT_LEN: usize = 0x40;
    static OBJECT: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SHARED_HANDLE_INITIALIZE, OBJECT_LEN).map(|pointer| pointer as usize)
    });
    static mut BOOTSTRAP_CALLS: u32 = 0;
    static mut BOOTSTRAP_OBJECT: u32 = 0;

    unsafe extern "C" fn recording_bootstrap() {
        BOOTSTRAP_CALLS += 1;
        SHARED_HANDLE_GLOBAL = BOOTSTRAP_OBJECT;
    }

    unsafe fn reset(object: *mut u32, refcount: u32) {
        core::ptr::write_bytes(object.cast::<u8>(), 0, OBJECT_LEN);
        object.add(SHARED_HANDLE_REFCOUNT_WORD).write(refcount);
        SHARED_HANDLE_GLOBAL = object as usize as u32;
        SHARED_HANDLE_BOOTSTRAP = recording_bootstrap;
        BOOTSTRAP_CALLS = 0;
        BOOTSTRAP_OBJECT = 0;
    }

    #[test]
    fn stores_global_object_and_retains_it_with_wrapping_count() {
        let _guard = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let Some(object) = *OBJECT else {
            assert!(note_missing_u32_fixture("cxx/shared_handle_initialize"));
            return;
        };

        unsafe {
            let object = object as *mut u32;
            reset(object, u32::MAX);
            let mut slot = 0xdead_beef;

            assert_eq!(shared_handle_initialize(addr_of_mut!(slot)), addr_of_mut!(slot));
            assert_eq!(slot, object as usize as u32);
            assert_eq!(object.add(SHARED_HANDLE_REFCOUNT_WORD).read(), 0);
            assert_eq!(BOOTSTRAP_CALLS, 0);
        }
    }

    #[test]
    fn bootstraps_a_null_global_then_reloads_and_retains_it() {
        let _guard = SHARED_HANDLE_INITIALIZE_TEST_LOCK.lock();
        let Some(object) = *OBJECT else {
            assert!(note_missing_u32_fixture("cxx/shared_handle_initialize"));
            return;
        };

        unsafe {
            let object = object as *mut u32;
            reset(object, 41);
            SHARED_HANDLE_GLOBAL = 0;
            BOOTSTRAP_OBJECT = object as usize as u32;
            let mut slot = 0;

            assert_eq!(shared_handle_initialize(addr_of_mut!(slot)), addr_of_mut!(slot));
            assert_eq!(BOOTSTRAP_CALLS, 1);
            assert_eq!(slot, object as usize as u32);
            assert_eq!(object.add(SHARED_HANDLE_REFCOUNT_WORD).read(), 42);
        }
    }
}
