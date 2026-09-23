//! The record-manager singleton accessor.
//!
//! Port:
//! - [`record_manager_get`] — original: `FUN_081c83b4` @ `0x081c83b4`
//!   (**104 bytes: 88 bytes of code plus its 16-byte literal pool; 20 direct
//!   `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM ends its code at `0x081c840c`; the four pool words at
//! `0x081c840c..0x081c8418` name the private guard state (`0x089cfd4c`),
//! fixed object (`0x08ad1f70`), `__dso_handle` (`0x089ca09c`), and registered
//! destructor (`0x081bdae8`). The next function begins at `0x081c841c`, so
//! Ghidra's reported 88-byte code extent omits the pool.
//!
//! The object owns a 128-entry primary record table and a 32-entry secondary
//! table. The unported constructor `FUN_081c8954` builds those tables and
//! finishes with the mutex at `this + 0xcd4`; therefore the fixed object's
//! exact observed extent is 0xcd8 bytes. The class identity does not survive
//! in the image, so `record_manager` describes the tables it owns rather than
//! inventing a C++ class name.
//!
//! ## Algorithm
//!
//! This is the ADS function-local-static sequence: test guard bit 0, acquire
//! the guard if clear, construct the fixed object, register the constructor's
//! return with `cxa_atexit`, release the guard, set the adjacent byte flag if
//! it was zero, then reload and return the fixed object literal. All twenty
//! callers use plain `bl`; none conditionally skip the accessor.
//!
//! ## Deliberate deviations
//!
//! The firmware's runtime RAM globals are crate statics, preserving their
//! zeroed pre-init state. The unported constructor is a replaceable seam whose
//! default zeroes the observed object extent. The destructor pool word is not
//! a callable function entry: `0x081bdae8` is an interior tail that branches
//! to a frame teardown at `0x081bda64` without establishing that frame. It
//! cannot safely run as a shutdown handler, and retailOS never runs this
//! chain, so the registered Rust handler is deliberately a no-op.
//!
//! - [`record_manager_current_record_status_failed`] — original:
//!   `FUN_081c8544` @ `0x081c8544` (**128 bytes**,
//!   `0x081c8544..0x081c85c4`; the next function begins at `0x081c85c4`).
//!   Raw ARM decoding finds four plain `bl` calls and zero predicated `bl`
//!   calls: selector initialization, registration initialization, current
//!   record lookup, and registration destruction.
//!
//!   It forms a kind-two registration over the manager subobject at `+0xa0c`,
//!   fetches its selected record handle, and returns one when no handle exists
//!   or that handle's vtable slot `+0x5c` reports a nonzero status. The
//!   registration is always destroyed before return. On 64-bit hosts the
//!   target's three-word registration is copied into a local target-layout
//!   view before calling the existing current-record port, and virtual dispatch
//!   uses a test seam because a target vtable word cannot contain a host
//!   function pointer. Firmware builds retain the native layout and indirect
//!   call exactly.


use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// The final mutex word is at `this + 0xcd4` in `FUN_081c8954`.
pub const RECORD_MANAGER_SIZE: usize = 0xcd8;

/// The fixed object's one-time-init guard (original: `0x089cfd50`).
pub static mut RECORD_MANAGER_GUARD: u32 = 0;

/// The adjacent byte state flag (original: `0x089cfd4c`).
pub static mut RECORD_MANAGER_READY: u8 = 0;

/// Fixed record-manager storage (original: `0x08ad1f70`).
pub static mut RECORD_MANAGER: [u8; RECORD_MANAGER_SIZE] = [0; RECORD_MANAGER_SIZE];

/// An ADS C++ constructor: receives the fixed storage and returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// The unported `FUN_081c8954` default: zero only the known object extent.
unsafe extern "C" fn zeroing_record_manager_ctor(this: *mut u8) -> *mut u8 {
    for offset in 0..RECORD_MANAGER_SIZE {
        this.add(offset).write_volatile(0);
    }
    this
}

/// Constructor seam for `FUN_081c8954` (`bl` at `0x081c83dc`).
pub static mut RECORD_MANAGER_CTOR: Constructor = zeroing_record_manager_ctor;

/// `__dso_handle`, the third `cxa_atexit` argument at `0x081c83e0`.
const DSO_HANDLE: i32 = 0x089ca09c;

/// Deliberately inert replacement for the invalid handler pointer at
/// `0x081bdae8`; see the module header.
unsafe extern "C" fn record_manager_destructor(_object: *mut c_void) {}

/// record_manager_get — original: `FUN_081c83b4` @ `0x081c83b4` (104 bytes:
/// 88 bytes of code plus 16-byte literal pool; 20 direct, unconditional `bl`
/// call sites, binary-verified by decoding every ARM B/BL word).
///
/// Lazily constructs and returns the fixed record manager. The getter always
/// reloads the object literal after initialization; it does not return the
/// constructor's result. A bit-0-clear, nonzero guard takes the slow path but
/// is refused by `cxa_guard_acquire`, exactly like the ARM sequence.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_manager_get")]
pub unsafe extern "C" fn record_manager_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(RECORD_MANAGER_GUARD);
    let object = core::ptr::addr_of_mut!(RECORD_MANAGER) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_CTOR))(object);
        cxa_atexit(this as *mut c_void, record_manager_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    if core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_READY)) == 0 {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(RECORD_MANAGER_READY), 1);
    }
    object
}

/// ABI of the selected record handle's vtable slot at `+0x5c`.
pub type CurrentRecordStatus = unsafe extern "C" fn(*mut u8, u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_record_status(_record: *mut u8, _status: u32) -> i32 {
    panic!("install record-manager current-record host operations before dispatch")
}

/// Host operation replacing the target-width selected-record vtable dispatch.
#[cfg(not(target_os = "none"))]
pub static mut RECORD_MANAGER_CURRENT_RECORD_STATUS: CurrentRecordStatus =
    missing_current_record_status;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_record_status(record: *mut u8, status: u32) -> i32 {
    let vtable = record.cast::<u32>().read() as usize;
    let dispatch = (vtable as *const u32).add(0x5c / 4).read() as usize;
    core::mem::transmute::<usize, CurrentRecordStatus>(dispatch)(record, status)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_record_status(record: *mut u8, status: u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_CURRENT_RECORD_STATUS))(record, status)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_record_status_6c(record: *mut u8, status: u32) -> i32 {
    let vtable = record.cast::<u32>().read() as usize;
    let dispatch = (vtable as *const u32).add(0x6c / 4).read() as usize;
    core::mem::transmute::<usize, CurrentRecordStatus>(dispatch)(record, status)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_record_status_6c(record: *mut u8, status: u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(RECORD_MANAGER_CURRENT_RECORD_STATUS))(record, status)
}


/// record_manager_current_record_status_failed — original: `FUN_081c8544` @
/// `0x081c8544` (128 bytes; four plain direct `bl` calls, zero predicated).
///
/// Builds a kind-two registration for `record_manager + 0xa0c` using
/// `selector`, then reports failure when its selected handle is absent or its
/// vtable `+0x5c` status is nonzero. The registration destructor runs on both
/// paths. On 64-bit hosts only, the temporary registration is copied to an
/// explicit three-word target view for the already-ported target-width current
/// record lookup; virtual dispatch goes through
/// [`RECORD_MANAGER_CURRENT_RECORD_STATUS`]. Those are deliberate host ABI
/// adaptations, not firmware behavior.
///
/// # Safety
///
/// `record_manager + 0xa0c` must meet the registration helper and selected
/// record-handle requirements. A nonzero selected handle must identify an
/// object whose vtable slot `+0x5c` has this function's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_manager_current_record_status_failed(
    record_manager: *mut u8,
    status: u32,
    selector: u32,
) -> u32 {
    use crate::app::current_record_handle::{current_record_handle, CurrentRecordCursor};
    use crate::app::registration_handle::{
        registration_handle_destroy, registration_handle_init, RegistrationHandle,
    };
    use crate::app::selector_pair_init::selector_pair_init;

    let mut selector_pair = [0u32; 2];
    selector_pair_init(selector_pair.as_mut_ptr(), selector, 0);

    let mut registration = core::mem::MaybeUninit::<RegistrationHandle>::uninit();
    let registration = registration_handle_init(
        registration.as_mut_ptr(),
        record_manager.add(0xa0c),
        2,
        selector_pair.as_ptr(),
    );

    #[cfg(target_os = "none")]
    let record = current_record_handle(registration.cast::<CurrentRecordCursor>()) as *mut u8;

    #[cfg(not(target_os = "none"))]
    let record = {
        #[repr(C)]
        struct TargetRegistrationHandle {
            vtable: u32,
            owner: u32,
            slot_index: i32,
        }
        let target_registration = TargetRegistrationHandle {
            vtable: (*registration).vtable,
            owner: (*registration).owner as usize as u32,
            slot_index: (*registration).slot_index,
        };
        current_record_handle(
            core::ptr::addr_of!(target_registration).cast::<CurrentRecordCursor>(),
        ) as *mut u8
    };

    let failed = record.is_null() || current_record_status(record, status) != 0;
    registration_handle_destroy(registration);
    failed as u32
}

/// record_manager_current_record_status_6c_failed — original:
/// `FUN_081c85c4` @ `0x081c85c4` (128 bytes,
/// `0x081c85c4..0x081c8644`; the next independently linked function begins
/// at `0x081c8644`). Raw ARM decoding finds four plain direct `bl` calls
/// (`0x081d9698`, `0x081d96a0`, `0x0829e1b4`, and `0x081d9734`) and zero
/// predicated direct `bl` calls.
///
/// Builds a kind-two registration for `record_manager + 0xa0c` from
/// `selector`, then reports failure when no selected record exists or that
/// record's vtable slot `+0x6c` returns nonzero for `status`. It always
/// destroys the registration before returning.
///
/// Deliberate deviation: on 64-bit hosts, the temporary registration is
/// copied to an explicit three-word target-layout view before the
/// target-width current-record lookup, and dispatch uses
/// [`RECORD_MANAGER_CURRENT_RECORD_STATUS`] because a target vtable word
/// cannot hold a host function pointer. Firmware retains the native layout
/// and indirect vtable dispatch.
///
/// # Safety
///
/// `record_manager + 0xa0c` must meet the registration helper and selected
/// record-handle requirements. A nonzero selected handle must identify an
/// object whose vtable slot `+0x6c` has this function's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_manager_current_record_status_6c_failed(
    record_manager: *mut u8,
    status: u32,
    selector: u32,
) -> u32 {
    use crate::app::current_record_handle::{current_record_handle, CurrentRecordCursor};
    use crate::app::registration_handle::{
        registration_handle_destroy, registration_handle_init, RegistrationHandle,
    };
    use crate::app::selector_pair_init::selector_pair_init;

    let mut selector_pair = [0u32; 2];
    selector_pair_init(selector_pair.as_mut_ptr(), selector, 0);

    let mut registration = core::mem::MaybeUninit::<RegistrationHandle>::uninit();
    let registration = registration_handle_init(
        registration.as_mut_ptr(),
        record_manager.add(0xa0c),
        2,
        selector_pair.as_ptr(),
    );

    #[cfg(target_os = "none")]
    let record = current_record_handle(registration.cast::<CurrentRecordCursor>()) as *mut u8;

    #[cfg(not(target_os = "none"))]
    let record = {
        #[repr(C)]
        struct TargetRegistrationHandle {
            vtable: u32,
            owner: u32,
            slot_index: i32,
        }
        let target_registration = TargetRegistrationHandle {
            vtable: (*registration).vtable,
            owner: (*registration).owner as usize as u32,
            slot_index: (*registration).slot_index,
        };
        current_record_handle(
            core::ptr::addr_of!(target_registration).cast::<CurrentRecordCursor>(),
        ) as *mut u8
    };

    let failed = record.is_null() || current_record_status_6c(record, status) != 0;
    registration_handle_destroy(registration);
    failed as u32
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
    use crate::app::registration_handle::{
        RegistrationHandleInitOps, DEFAULT_REGISTRATION_HANDLE_INIT_OPS,
        REGISTRATION_HANDLE_INIT_OPS,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;


    static RECORD_MANAGER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();
    static CURRENT_RECORD_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RECORD_MANAGER_CURRENT_RECORD_STATUS, 0x2000)
            .map(|pointer| pointer as usize)
    });
    static mut CURRENT_RECORD_STATUS_RESULT: i32 = 0;
    static mut CURRENT_RECORD_STATUS_CALL: Option<(*mut u8, u32)> = None;


    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: record_manager_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    unsafe extern "C" fn acquire_current_record(owner: *mut u8, _slot: u32) -> *mut u8 {
        owner
    }

    unsafe extern "C" fn reject_current_record(_owner: *mut u8, _slot: u32) -> *mut u8 {
        ptr::null_mut()
    }


    unsafe extern "C" fn dispatch_current_record(record: *mut u8, status: u32) -> i32 {
        CURRENT_RECORD_STATUS_CALL = Some((record, status));
        CURRENT_RECORD_STATUS_RESULT
    }

    unsafe fn install_current_record_ops(acquire: crate::app::registration_handle::RegistrationSlotAcquire) {
        REGISTRATION_HANDLE_INIT_OPS = RegistrationHandleInitOps {
            find_slot: DEFAULT_REGISTRATION_HANDLE_INIT_OPS.find_slot,
            acquire_slot: acquire,
        };
        RECORD_MANAGER_CURRENT_RECORD_STATUS = dispatch_current_record;
        CURRENT_RECORD_STATUS_CALL = None;
    }

    unsafe fn restore_current_record_ops() {
        REGISTRATION_HANDLE_INIT_OPS = DEFAULT_REGISTRATION_HANDLE_INIT_OPS;
        RECORD_MANAGER_CURRENT_RECORD_STATUS = missing_current_record_status;
        CURRENT_RECORD_STATUS_CALL = None;
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(RECORD_MANAGER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = RECORD_MANAGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORD_MANAGER_GUARD = 0;
            RECORD_MANAGER_READY = 0;
            for offset in 0..RECORD_MANAGER_SIZE {
                storage().add(offset).write(0xa5);
            }
            RECORD_MANAGER_CTOR = zeroing_record_manager_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            RECORD_MANAGER_CTOR = zeroing_record_manager_ctor;
            RECORD_MANAGER_GUARD = 0;
            RECORD_MANAGER_READY = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_marks_ready_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            assert_eq!(record_manager_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![storage()]);
            assert_eq!(RECORD_MANAGER_GUARD, 1, "acquire publishes the guard");
            assert_eq!(RECORD_MANAGER_READY, 1, "the byte flag is set after initialization");
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage(), "constructor return is registered");
            assert_eq!((*node).handler as usize, record_manager_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_manager_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            record_manager_get();
            storage().add(0xa0c).write(0x31);
            assert_eq!(record_manager_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1);
            assert_eq!(storage().add(0xa0c).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn guard_edge_cases_skip_construction_but_still_mark_ready() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            RECORD_MANAGER_GUARD = 3;
            assert_eq!(record_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
            assert_eq!(RECORD_MANAGER_READY, 1);
            assert!(shutdown_chain_head().read().is_null());

            RECORD_MANAGER_GUARD = 2;
            RECORD_MANAGER_READY = 0;
            assert_eq!(record_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty(), "acquire rejects nonzero guards");
            assert_eq!(RECORD_MANAGER_GUARD, 2);
            assert_eq!(RECORD_MANAGER_READY, 1);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            RECORD_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(record_manager_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn default_constructor_zeroes_the_observed_extent_and_noop_destructor_preserves_it() {
        let lock = reset();
        unsafe {
            record_manager_get();
            assert!((0..RECORD_MANAGER_SIZE).all(|offset| storage().add(offset).read() == 0));
            storage().add(0xcd4).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0xcd4).read(), 0xa5, "invalid stock handler is inert");
        }
        restore(lock);
    }

    #[test]
    fn object_extent_covers_the_last_constructor_mutex_word() {
        assert_eq!(RECORD_MANAGER_SIZE, 0xcd8);
    }
    #[test]
    fn current_record_status_reports_failure_when_registration_has_no_handle() {
        let lock = reset();
        unsafe {
            install_current_record_ops(reject_current_record);
            assert_eq!(record_manager_current_record_status_failed(storage(), 7, 3), 1);
            assert_eq!(CURRENT_RECORD_STATUS_CALL, None);
            restore_current_record_ops();
        }
        restore(lock);
    }

    #[test]
    fn current_record_status_returns_vtable_result_and_preserves_status_argument() {
        let lock = reset();
        let Some(base) = *CURRENT_RECORD_FIXTURE else {
            assert!(note_missing_u32_fixture("app::record_manager current-record status"));
            restore(lock);
            return;
        };
        unsafe {
            let base = base as *mut u8;
            base.write_bytes(0, 0x2000);
            let records = base.add(0x1000);
            records.add(4).cast::<u32>().write(0x1234_5678);
            let manager = base;
            manager.add(0xa0c + 4).cast::<u32>().write(records as usize as u32);
            manager.add(0xa0c + 8).cast::<i32>().write(0);

            install_current_record_ops(acquire_current_record);
            CURRENT_RECORD_STATUS_RESULT = 0;
            assert_eq!(record_manager_current_record_status_failed(manager, 0xfeed_face, 9), 0);
            assert_eq!(CURRENT_RECORD_STATUS_CALL, Some((0x1234_5678usize as *mut u8, 0xfeed_face)));

            CURRENT_RECORD_STATUS_RESULT = -1;
            assert_eq!(record_manager_current_record_status_failed(manager, 0, 9), 1);
            restore_current_record_ops();
        }
        restore(lock);
    }

    #[test]
    fn current_record_status_6c_handles_absent_and_status_returning_records() {
        let lock = reset();
        unsafe {
            install_current_record_ops(reject_current_record);
            assert_eq!(record_manager_current_record_status_6c_failed(storage(), 7, 3), 1);
            assert_eq!(CURRENT_RECORD_STATUS_CALL, None);
            restore_current_record_ops();
        }

        let Some(base) = *CURRENT_RECORD_FIXTURE else {
            assert!(note_missing_u32_fixture("app::record_manager current-record status 6c"));
            restore(lock);
            return;
        };
        unsafe {
            let base = base as *mut u8;
            base.write_bytes(0, 0x2000);
            let records = base.add(0x1000);
            records.add(4).cast::<u32>().write(0x1234_5678);
            let manager = base;
            manager.add(0xa0c + 4).cast::<u32>().write(records as usize as u32);
            manager.add(0xa0c + 8).cast::<i32>().write(0);

            install_current_record_ops(acquire_current_record);
            CURRENT_RECORD_STATUS_RESULT = 0;
            assert_eq!(
                record_manager_current_record_status_6c_failed(manager, 0xfeed_face, 9),
                0
            );
            assert_eq!(
                CURRENT_RECORD_STATUS_CALL,
                Some((0x1234_5678usize as *mut u8, 0xfeed_face))
            );

            CURRENT_RECORD_STATUS_RESULT = -1;
            assert_eq!(record_manager_current_record_status_6c_failed(manager, 0, 9), 1);
            restore_current_record_ops();
        }
        restore(lock);
    }
}

