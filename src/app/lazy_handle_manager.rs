//! The lazy shared-handle manager singleton accessor.
//!
//! Port:
//! - [`lazy_handle_manager_get`] — original: `FUN_081bbf98` @ `0x081bbf98`
//!   (88 bytes: 72 bytes of code plus a 16-byte literal pool; **13 direct,
//!   unconditional plain `bl` call sites, no predicated forms or tail
//!   branches**, verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! The true extent ends at `0x081bbff0`, whose distinct `push` prologue starts
//! the manager's acquisition method. Ghidra's reported 72 bytes omits this
//! accessor's four literal-pool words.
//!
//! This is an ADS function-local static over the 16-byte manager at
//! `0x08ac8890`: a mutex pair, a cached handle, and an initialized byte. The
//! constructor (`FUN_081bc0c4` @ `0x081bc0c4`) and destructor target
//! (`0x081b1210`) are unported. Target builds call the verified constructor
//! entry directly; host tests substitute a recording constructor. The
//! destructor target is a real entry — raw ARM starts with `mov ip, r0` — but
//! its identity is not inferred, so target builds preserve its raw address and
//! host teardown uses a no-op callback.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const LAZY_HANDLE_MANAGER_ADDRESS: usize = 0x08ac_8890;
const LAZY_HANDLE_MANAGER_GUARD_ADDRESS: usize = 0x089c_c9fc;
const LAZY_HANDLE_MANAGER_CTOR_ADDRESS: usize = 0x081b_c0c4;
const LAZY_HANDLE_MANAGER_DESTRUCTOR_ADDRESS: usize = 0x081b_1210;
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Volatile bindings preserve the two direct ADS call boundaries that LLVM
/// would otherwise inline or erase in this small accessor.
type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut LAZY_HANDLE_MANAGER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut LAZY_HANDLE_MANAGER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

/// Fixed manager layout established by `FUN_081bc0c4`: it initializes the
/// mutex at +0x00, stores -1 at +0x08, and clears +0x0c.
#[repr(C)]
pub struct LazyHandleManager {
    pub mutex_words: [u32; 2],
    pub cached_handle: i32,
    pub initialized: u8,
    pub padding: [u8; 3],
}

/// The unported ADS constructor's ABI.
pub type LazyHandleManagerCtor = unsafe extern "C" fn(
    manager: *mut LazyHandleManager,
) -> *mut LazyHandleManager;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_lazy_handle_manager_ctor(
    manager: *mut LazyHandleManager,
) -> *mut LazyHandleManager {
    let constructor: LazyHandleManagerCtor = core::mem::transmute(LAZY_HANDLE_MANAGER_CTOR_ADDRESS);
    constructor(manager)
}

/// Host default only preserves the unported constructor's return ABI. Tests
/// install a concrete model before observing initialization.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_lazy_handle_manager_ctor(
    manager: *mut LazyHandleManager,
) -> *mut LazyHandleManager {
    manager
}

/// Constructor seam: device builds target the verified stock entry; host
/// tests replace it because `FUN_081bc0c4` is not ported.
pub static mut LAZY_HANDLE_MANAGER_CTOR: LazyHandleManagerCtor = {
    #[cfg(target_os = "none")]
    {
        firmware_lazy_handle_manager_ctor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_lazy_handle_manager_ctor
    }
};

#[cfg(target_os = "none")]
fn lazy_handle_manager_destructor() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(LAZY_HANDLE_MANAGER_DESTRUCTOR_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_lazy_handle_manager_destructor(_manager: *mut c_void) {}

#[cfg(not(target_os = "none"))]
fn lazy_handle_manager_destructor() -> ShutdownHandlerFn {
    host_lazy_handle_manager_destructor
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostLazyHandleManagerState {
    guard: u32,
    manager: LazyHandleManager,
}

#[cfg(not(target_os = "none"))]
static mut HOST_LAZY_HANDLE_MANAGER_STATE: HostLazyHandleManagerState = HostLazyHandleManagerState {
    guard: 0,
    manager: LazyHandleManager {
        mutex_words: [0; 2],
        cached_handle: 0,
        initialized: 0,
        padding: [0; 3],
    },
};

#[inline(always)]
unsafe fn lazy_handle_manager_state() -> (*mut u32, *mut LazyHandleManager) {
    #[cfg(target_os = "none")]
    {
        (
            LAZY_HANDLE_MANAGER_GUARD_ADDRESS as *mut u32,
            LAZY_HANDLE_MANAGER_ADDRESS as *mut LazyHandleManager,
        )
    }

    #[cfg(not(target_os = "none"))]
    {
        let state = core::ptr::addr_of_mut!(HOST_LAZY_HANDLE_MANAGER_STATE);
        (
            core::ptr::addr_of_mut!((*state).guard),
            core::ptr::addr_of_mut!((*state).manager),
        )
    }
}

#[inline(always)]
unsafe fn lazy_handle_manager_ctor() -> LazyHandleManagerCtor {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_HANDLE_MANAGER_CTOR))
}
#[inline(always)]
unsafe fn lazy_handle_manager_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_HANDLE_MANAGER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn lazy_handle_manager_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(LAZY_HANDLE_MANAGER_CXA_GUARD_RELEASE))
}

/// lazy_handle_manager_get — original: `FUN_081bbf98` @ `0x081bbf98` (88
/// bytes: 72 bytes of code and a 16-byte literal pool; 13 unconditional plain
/// `bl` call sites, no predicated forms or tail branches, binary-verified).
///
/// Returns the fixed manager at `0x08ac8890`. When guard bit 0 is clear, the
/// accessor asks the complete guard word for ownership, constructs that fixed
/// manager, registers the *constructor result* with `cxa_atexit`, and releases
/// the guard. It always reloads and returns the fixed manager pointer, never
/// the constructor result.
///
/// Deliberate deviations: target calls the unported constructor and real
/// destructor entry by their verified raw addresses; host state and a no-op
/// destructor exist only to test this accessor without inventing either
/// callee's identity.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.lazy_handle_manager_get")]
#[inline(never)]
pub unsafe extern "C" fn lazy_handle_manager_get() -> *mut LazyHandleManager {
    let (guard, manager) = lazy_handle_manager_state();
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let this = lazy_handle_manager_ctor()(manager);
        lazy_handle_manager_cxa_atexit()(this.cast::<c_void>(), lazy_handle_manager_destructor(), DSO_HANDLE);
        lazy_handle_manager_cxa_guard_release()(guard);
    }
    manager
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static LAZY_HANDLE_MANAGER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: Vec<*mut LazyHandleManager> = Vec::new();
    static mut CTOR_RESULT: *mut LazyHandleManager = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(
        manager: *mut LazyHandleManager,
    ) -> *mut LazyHandleManager {
        (*ptr::addr_of_mut!(CTOR_CALLS)).push(manager);
        (*manager).cached_handle = -1;
        (*manager).initialized = 1;
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: host_lazy_handle_manager_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    unsafe fn state() -> (*mut u32, *mut LazyHandleManager) {
        lazy_handle_manager_state()
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = LAZY_HANDLE_MANAGER_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let (guard, manager) = state();
            ptr::write(guard, 0);
            ptr::write(
                manager,
                LazyHandleManager {
                    mutex_words: [0xa5a5_a5a5; 2],
                    cached_handle: 0x5a5a_5a5a,
                    initialized: 0xa5,
                    padding: [0xa5; 3],
                },
            );
            LAZY_HANDLE_MANAGER_CTOR = host_lazy_handle_manager_ctor;
            CTOR_RESULT = manager;
            (*ptr::addr_of_mut!(CTOR_CALLS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            ptr::write(shutdown_chain_head(), ptr::null_mut());
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            LAZY_HANDLE_MANAGER_CTOR = host_lazy_handle_manager_ctor;
            ptr::write(state().0, 0);
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_manager() {
        let lock = reset();
        unsafe {
            let (_guard, manager) = state();
            LAZY_HANDLE_MANAGER_CTOR = recording_ctor;
            assert_eq!(lazy_handle_manager_get(), manager);
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![manager]);
            assert_eq!(ptr::read(state().0), 1);
            assert_eq!((*manager).cached_handle, -1);
            assert_eq!((*manager).initialized, 1);

            let node = ptr::read(shutdown_chain_head());
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut LazyHandleManager, manager);
            assert_eq!((*node).handler as usize, host_lazy_handle_manager_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
            assert!((*node).next.is_null(), "registered exactly once");
        }
        restore(lock);
    }

    #[test]
    fn initialized_fast_path_preserves_manager_without_rerunning_constructor() {
        let lock = reset();
        unsafe {
            let (_guard, manager) = state();
            LAZY_HANDLE_MANAGER_CTOR = recording_ctor;
            lazy_handle_manager_get();
            (*manager).cached_handle = 0x1234_5678;
            assert_eq!(lazy_handle_manager_get(), manager);
            assert_eq!((*ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!((*manager).cached_handle, 0x1234_5678);
            assert!((*ptr::read(shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_is_refused_and_returns_fixed_manager() {
        let lock = reset();
        unsafe {
            let (guard, manager) = state();
            LAZY_HANDLE_MANAGER_CTOR = recording_ctor;
            ptr::write(guard, 2);
            assert_eq!(lazy_handle_manager_get(), manager);
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(ptr::read(guard), 2);
            assert!(ptr::read(shutdown_chain_head()).is_null());
            assert_eq!((*manager).cached_handle, 0x5a5a_5a5a);
        }
        restore(lock);
    }

    #[test]
    fn registration_uses_constructor_result_but_return_uses_fixed_manager() {
        let lock = reset();
        unsafe {
            let (_guard, manager) = state();
            LAZY_HANDLE_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = (manager as *mut u8).add(core::mem::size_of::<u32>()).cast();
            assert_eq!(lazy_handle_manager_get(), manager);
            assert_eq!(
                (*ptr::read(shutdown_chain_head())).arg as *mut LazyHandleManager,
                CTOR_RESULT,
            );
        }
        restore(lock);
    }
}
