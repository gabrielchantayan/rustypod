//! The StreamCache mass-storage-manager singleton accessor.
//!
//! Port:
//! - [`stream_cache_mass_storage_manager_get`] — original: `FUN_08228068` @
//!   `0x08228068` (**88 bytes: 72 bytes of code plus its 16-byte literal
//!   pool; 19 direct `bl` call sites, all unconditional and zero
//!   predicated**).
//!
//! Raw ARM ends its code at `0x082280b0`; the four pool words at
//! `0x082280b0..0x082280c0` name the private guard (`0x08a09d74`), fixed
//! object (`0x08ae4b4c`), `__dso_handle` (`0x089ca09c`), and registered
//! handler (`0x0821d440`). The next separately linked function starts at
//! `0x082280c0`, so Ghidra's 72-byte code extent drops the literal pool.
//!
//! ## Algorithm
//!
//! Test guard bit 0; if clear and `cxa_guard_acquire` accepts the whole
//! zero-valued word, construct the fixed manager through `FUN_08228270`,
//! register the constructor return with `cxa_atexit`, and release the guard.
//! Reload and return the fixed object literal regardless of the constructor
//! return value. Every direct caller is a plain `bl`; none conditionally
//! skips this accessor.
//!
//! ## Deliberate deviations
//!
//! On-device the constructor seam calls the retained retailOS constructor at
//! `0x08228270`. Host tests replace it because that code is unavailable there;
//! their default is an inert return of the already zero-initialized fixed
//! storage. The registered word `0x0821d440` is not a function entry: the
//! actual frame-establishing prologue begins at `0x0821d43c`, so entering at
//! `+4` eventually pops an unestablished frame. The Rust shutdown handler is
//! deliberately a no-op rather than inventing a callable destructor.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;
use crate::drivers::timer::{timer_arm, timer_set_delay};
use crate::kernel::gateway_request_blocking::gateway_request_blocking;
use crate::kernel::gateway_request::gateway_request_timed;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The worker at `FUN_082280c0` reads the final word at `this + 0x30`.
pub const STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE: usize = 0x34;

/// Fixed manager storage (original: `0x08ae4b4c`).
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER: [u8; STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE] =
    [0; STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE];

/// The function-local-static guard (original: `0x08a09d74`).
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD: u32 = 0;

/// An ADS C++ constructor: receives the fixed storage and returns `this`.
pub type MassStorageManagerCtor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_mass_storage_manager_ctor(this: *mut u8) -> *mut u8 {
    let constructor: MassStorageManagerCtor = core::mem::transmute(0x0822_8270usize);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_mass_storage_manager_ctor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor boundary for `FUN_08228270` (`bl` at `0x08228090`).
#[cfg(target_os = "none")]
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR: MassStorageManagerCtor =
    firmware_mass_storage_manager_ctor;

/// Host stand-in for the retailOS constructor; tests install a recording seam.
#[cfg(not(target_os = "none"))]
pub static mut STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR: MassStorageManagerCtor =
    host_mass_storage_manager_ctor;

/// `__dso_handle`, the third `cxa_atexit` argument at `0x08228098`.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// Safe replacement for invalid handler word `0x0821d440`; see module docs.
unsafe extern "C" fn mass_storage_manager_destructor(_object: *mut c_void) {}

/// stream_cache_mass_storage_manager_get — original: `FUN_08228068` @
/// `0x08228068` (88 bytes: 72 bytes of code and a 16-byte literal pool; 19
/// direct unconditional `bl` call sites, binary-verified by decoding every
/// ARM B/BL word).
///
/// Lazily constructs and returns the fixed manager. The accessor reloads the
/// fixed-object literal after initialization, never returning the constructor
/// result. A nonzero guard with bit 0 clear reaches `cxa_guard_acquire`, which
/// refuses it exactly as the raw ARM sequence does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_cache_mass_storage_manager_get")]
pub unsafe extern "C" fn stream_cache_mass_storage_manager_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD);
    let manager = core::ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER) as *mut u8;
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = core::ptr::read_volatile(core::ptr::addr_of!(STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR))(manager);
        cxa_atexit(this as *mut c_void, mass_storage_manager_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    manager
}

/// 32-bit firmware layout of the manager's gateway/timer controller.
///
/// `Mutex` occupies two words on target. Its host pointer field is naturally
/// wider, but named fields rather than byte offsets preserve every access
/// relationship without overlapping fields in host fixtures.
#[repr(C)]
pub struct StreamCacheMassStorageManagerTimer {
    /// +0x00: set after the first blocking gateway request.
    pub gateway_requested: u8,
    /// +0x01: set by a zero delay; suppresses later nonzero schedules.
    pub stopped: u8,
    /// +0x02: set while the embedded timer is armed.
    pub timer_pending: u8,
    _padding: u8,
    /// +0x04: mutex guarding all state below.
    pub mutex: Mutex,
    /// +0x0c: constructor-owned timer service handle.
    pub timer_service: u32,
    /// +0x10: embedded timer consumed by the timer driver.
    pub timer: [u8; 0x20],
    /// +0x30: context word retained for the worker at 0x082280c0.
    pub context: u32,
}

/// The one `context` value selecting gateway request payload 0x20 instead of
/// the default 0x1b (the raw literal at 0x082281fc).
const GATEWAY_PAYLOAD_SPECIAL_CONTEXT: u32 = 0x6368_7363;
const GATEWAY_PAYLOAD_DEFAULT: usize = 0x1b;
const GATEWAY_PAYLOAD_SPECIAL: usize = 0x20;

/// stream_cache_mass_storage_manager_update_timer — original:
/// `FUN_08228154` @ `0x08228154` (172 bytes: 168 bytes of code and the
/// literal-pool word at `0x082281fc`; the next separately linked entry opens
/// at `0x08228200`). Eight direct inbound call sites are all unconditional
/// `bl`: 0x081af5a4, 0x081c876c, 0x08201754, 0x08206338, 0x08206478,
/// 0x082066a0, 0x082068f8, and 0x08206aa4.
///
/// Under the controller mutex, posts one blocking gateway request on the
/// first invocation, clears and trace-validates a pending embedded timer,
/// then either marks the controller stopped for a zero delay or, while not
/// stopped, retains `context`, programs the timer delay, and arms it. The
/// raw `bic r9, r5, r3` forwards only `!request_flags & 1` to the gateway.
///
/// Deliberate deviations: calls the already ported mutex, gateway, and timer
/// functions directly instead of their three tail-thunk addresses
/// (0x080cb81c, 0x080cb824, and the direct timer entries). This has identical
/// observable behavior; Rust returns the explicit zero the raw function
/// places in r8.
///
/// # Safety
///
/// `this` must point to a valid [`StreamCacheMassStorageManagerTimer`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_cache_mass_storage_manager_update_timer")]
pub unsafe extern "C" fn stream_cache_mass_storage_manager_update_timer(
    this: *mut StreamCacheMassStorageManagerTimer,
    context: u32,
    delay: u32,
    request_flags: u32,
) -> u32 {
    mutex_lock(core::ptr::addr_of_mut!((*this).mutex));

    if (*this).gateway_requested == 0 {
        let payload = if context == GATEWAY_PAYLOAD_SPECIAL_CONTEXT {
            GATEWAY_PAYLOAD_SPECIAL
        } else {
            GATEWAY_PAYLOAD_DEFAULT
        };
        gateway_request_blocking(payload, ((!request_flags) & 1) as usize);
        (*this).gateway_requested = 1;
    }

    if (*this).timer_pending != 0 {
        (*this).timer_pending = 0;
        crate::drivers::timer::timer_trace_assert((*this).timer.as_mut_ptr());
    }

    if delay == 0 {
        (*this).stopped = 1;
    } else if (*this).stopped == 0 {
        (*this).context = context;
        (*this).timer_pending = 1;
        timer_set_delay((*this).timer.as_mut_ptr(), delay);
        timer_arm((*this).timer.as_mut_ptr());
    }

    mutex_unlock(core::ptr::addr_of_mut!((*this).mutex));
    0
}

/// stream_cache_mass_storage_manager_clear_timer_state — original:
/// `FUN_08228200` @ `0x08228200` (108 bytes: 104 bytes of code plus the
/// literal-pool word at `0x0822826c`; the next separately linked entry opens
/// at `0x08228270`). Seven direct inbound `bl` call sites comprise six
/// unconditional calls at 0x081af724, 0x082063f8, 0x082064d8, 0x082066ec,
/// 0x08206a3c, and 0x08206af4, plus one predicated `bleq` at 0x08228124.
/// One unconditional tail `b` at 0x08201a68 also reaches this function; the
/// predicated call invokes this cleanup only when its caller's preceding
/// comparison is equal.
///
/// Under the controller mutex, a pending gateway request posts the timed
/// gateway message (payload 0x20 only for the special context, otherwise
/// 0x1b) and is cleared. A pending embedded timer is cleared and
/// trace-validated, then the stopped byte is cleared. The raw function
/// explicitly returns zero.
///
/// Deliberate deviations: this calls the ported mutex, timed-gateway, and
/// timer-trace implementations directly rather than their retailOS call
/// addresses. The behavior and call ordering are preserved.
///
/// # Safety
///
/// `this` must point to a valid [`StreamCacheMassStorageManagerTimer`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_cache_mass_storage_manager_clear_timer_state")]
pub unsafe extern "C" fn stream_cache_mass_storage_manager_clear_timer_state(
    this: *mut StreamCacheMassStorageManagerTimer,
    context: u32,
    timeout: u32,
) -> u32 {
    mutex_lock(core::ptr::addr_of_mut!((*this).mutex));

    if (*this).gateway_requested != 0 {
        let payload = if context == GATEWAY_PAYLOAD_SPECIAL_CONTEXT {
            GATEWAY_PAYLOAD_SPECIAL
        } else {
            GATEWAY_PAYLOAD_DEFAULT
        };
        gateway_request_timed(payload, timeout as usize);
        (*this).gateway_requested = 0;
    }

    if (*this).timer_pending != 0 {
        (*this).timer_pending = 0;
        crate::drivers::timer::timer_trace_assert((*this).timer.as_mut_ptr());
    }

    (*this).stopped = 0;
    mutex_unlock(core::ptr::addr_of_mut!((*this).mutex));
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_PENDING_HEAD};
    use crate::kernel::gateway_request_blocking::GATEWAY_READY_WAIT;
    use crate::kernel::task_lock::{RomThunkOps, ROM_KERNEL};
    use crate::kernel::task_lock::tests::OPS_LOCK as TASK_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use crate::testing::TIMER_OPS_TEST_LOCK;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::MutexGuard as ParkingLotMutexGuard;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::sync::MutexGuard as StdMutexGuard;
    use std::vec::Vec;

    static TIMER_TRACE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static GATEWAY_DISPATCH_CALLS: AtomicUsize = AtomicUsize::new(0);


    unsafe extern "C" fn ready_gateway() {}

    unsafe extern "C" fn ignore_gateway_dispatch(_request: *mut u32) {
        GATEWAY_DISPATCH_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn ignore_gateway_semaphore(_semaphore: usize) -> usize {
        0
    }

    unsafe extern "C" fn record_timer_trace(_timer: *mut u8) {
        TIMER_TRACE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// Holds every shared seam reached by the gateway and timer paths and
    /// restores it on both test completion and unwinding.
    struct TimerUpdateRestore {
        _dispatch_lock: ParkingLotMutexGuard<'static, ()>,
        _task_lock: StdMutexGuard<'static, ()>,
        _timer_lock: StdMutexGuard<'static, ()>,
        dispatch: MessageDispatchVeneerOps,
        task_ops: RomThunkOps,
        timer_ops: TimerOps,
        gateway_wait: unsafe extern "C" fn(),
        pending_head: u32,
    }

    impl Drop for TimerUpdateRestore {
        fn drop(&mut self) {
            unsafe {
                MESSAGE_DISPATCH_VENEER_OPS = self.dispatch;
                ptr::addr_of_mut!(ROM_KERNEL).write_volatile(self.task_ops);
                ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.timer_ops);
                ptr::addr_of_mut!(GATEWAY_READY_WAIT).write_volatile(self.gateway_wait);
                ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(self.pending_head);
            }
        }
    }

    fn install_timer_update_recorders() -> TimerUpdateRestore {
        let dispatch_lock = DISPATCH_OPS_LOCK.lock();
        let task_lock = TASK_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let timer_lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            TIMER_TRACE_CALLS.store(0, Ordering::SeqCst);
            GATEWAY_DISPATCH_CALLS.store(0, Ordering::SeqCst);
            let dispatch = MESSAGE_DISPATCH_VENEER_OPS;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: ignore_gateway_dispatch,
            };
            let timer_ops = ptr::addr_of!(TIMER_OPS).read_volatile();
            let task_ops = ptr::addr_of!(ROM_KERNEL).read_volatile();
            let mut patched_task_ops = task_ops;
            patched_task_ops.rom_sem_wait = ignore_gateway_semaphore;
            patched_task_ops.rom_sem_signal = ignore_gateway_semaphore;
            ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched_task_ops);
            let mut patched_timer_ops = timer_ops;
            patched_timer_ops.trace_assert = record_timer_trace;
            patched_timer_ops.trace_validate = record_timer_trace;
            ptr::addr_of_mut!(TIMER_OPS).write_volatile(patched_timer_ops);
            let gateway_wait = ptr::addr_of!(GATEWAY_READY_WAIT).read_volatile();
            ptr::addr_of_mut!(GATEWAY_READY_WAIT).write_volatile(ready_gateway);
            let pending_head = ptr::addr_of!(TIMER_PENDING_HEAD).read_volatile();
            ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(0);
            TimerUpdateRestore {
                _dispatch_lock: dispatch_lock,
                _task_lock: task_lock,
                _timer_lock: timer_lock,
                dispatch,
                task_ops,
                timer_ops,
                gateway_wait,
                pending_head,
            }
        }
    }

    fn timer_delay(timer: &[u8; 0x20]) -> u32 {
        u32::from_le_bytes([timer[4], timer[5], timer[6], timer[7]])
    }

    #[test]
    fn update_timer_requests_once_replaces_pending_schedule_and_stops() {
        let _restore = install_timer_update_recorders();
        let mut controller = StreamCacheMassStorageManagerTimer {
            gateway_requested: 0,
            stopped: 0,
            timer_pending: 0,
            _padding: 0,
            mutex: crate::kernel::sync_mutex::Mutex {
                sem_cell: ptr::null_mut(),
                unused: 0,
            },
            timer_service: 0,
            timer: [0; 0x20],
            context: 0xdeaf_beef,
        };

        unsafe {
            assert_eq!(
                stream_cache_mass_storage_manager_update_timer(
                    &mut controller, GATEWAY_PAYLOAD_SPECIAL_CONTEXT, 37, 0,
                ),
                0
            );
        }
        assert_eq!(controller.gateway_requested, 1, "first call posts the gateway request");
        assert_eq!(controller.stopped, 0);
        assert_eq!(controller.timer_pending, 1);
        assert_eq!(controller.context, GATEWAY_PAYLOAD_SPECIAL_CONTEXT);
        assert_eq!(TIMER_TRACE_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(controller.timer[0x1c], 1, "the real timer_arm body ran");

        unsafe {
            stream_cache_mass_storage_manager_update_timer(&mut controller, 0xabcd_1234, 99, 1);
        }
        assert_eq!(controller.gateway_requested, 1, "gateway request is one-shot");
        assert_eq!(controller.timer_pending, 1, "new schedule re-pends the timer");
        assert_eq!(controller.context, 0xabcd_1234);
        assert_eq!(timer_delay(&controller.timer), 99);
        assert_eq!(
            TIMER_TRACE_CALLS.load(Ordering::SeqCst),
            4,
            "clearing a pending timer validates once, then timer_set_delay traces again"
        );
        unsafe {
            stream_cache_mass_storage_manager_update_timer(&mut controller, 0x1111_2222, 0, 0);
            stream_cache_mass_storage_manager_update_timer(&mut controller, 0x3333_4444, 123, 0);
        }
        assert_eq!(controller.stopped, 1, "zero delay permanently selects the stopped path");
        assert_eq!(controller.timer_pending, 0, "zero delay clears but does not re-pend");
        assert_eq!(controller.context, 0xabcd_1234, "stopped controller ignores later schedules");
        assert_eq!(timer_delay(&controller.timer), 99);
        assert_eq!(TIMER_TRACE_CALLS.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn clear_timer_state_posts_pending_gateway_and_clears_every_flag() {
        let _restore = install_timer_update_recorders();
        let mut controller = StreamCacheMassStorageManagerTimer {
            gateway_requested: 1,
            stopped: 1,
            timer_pending: 1,
            _padding: 0,
            mutex: crate::kernel::sync_mutex::Mutex {
                sem_cell: ptr::null_mut(),
                unused: 0,
            },
            timer_service: 0,
            timer: [0; 0x20],
            context: 0,
        };

        unsafe {
            assert_eq!(
                stream_cache_mass_storage_manager_clear_timer_state(
                    &mut controller, GATEWAY_PAYLOAD_SPECIAL_CONTEXT, 0,
                ),
                0
            );
        }
        assert_eq!(GATEWAY_DISPATCH_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(TIMER_TRACE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            [controller.gateway_requested, controller.stopped, controller.timer_pending],
            [0, 0, 0],
        );

        unsafe {
            stream_cache_mass_storage_manager_clear_timer_state(&mut controller, 0, u32::MAX);
        }
        assert_eq!(GATEWAY_DISPATCH_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(TIMER_TRACE_CALLS.load(Ordering::SeqCst), 1);
    }
    static MANAGER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_CALLS)).push(this);
        this.write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: mass_storage_manager_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(STREAM_CACHE_MASS_STORAGE_MANAGER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = MANAGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 0;
            for offset in 0..STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE {
                storage().add(offset).write(0xa5);
            }
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = host_mass_storage_manager_ctor;
            CTOR_RESULT = storage();
            (*ptr::addr_of_mut!(CTOR_CALLS)).clear();
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
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = host_mass_storage_manager_ctor;
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!(*ptr::addr_of!(CTOR_CALLS), std::vec![storage()]);
            assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD, 1);
            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered with cxa_atexit");
            assert_eq!((*node).arg as *mut u8, storage());
            assert_eq!((*node).handler as usize, mass_storage_manager_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_preserves_state_and_does_not_register_twice() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            stream_cache_mass_storage_manager_get();
            storage().add(0x30).write(0x31);
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!((*ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!(storage().add(0x30).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn guard_edge_cases_skip_construction() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 3;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());

            STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD = 2;
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert!((*ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_GUARD, 2);
        }
        restore(lock);
    }

    #[test]
    fn getter_returns_literal_while_shutdown_carries_constructor_result() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = storage().add(4);
            assert_eq!(stream_cache_mass_storage_manager_get(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut u8, storage().add(4));
        }
        restore(lock);
    }

    #[test]
    fn storage_covers_worker_final_word_and_noop_shutdown_preserves_it() {
        let lock = reset();
        unsafe {
            STREAM_CACHE_MASS_STORAGE_MANAGER_CTOR = recording_ctor;
            stream_cache_mass_storage_manager_get();
            storage().add(0x30).write(0xa5);
            lib_shutdown_chain(0);
            assert_eq!(storage().add(0x30).read(), 0xa5);
        }
        assert_eq!(STREAM_CACHE_MASS_STORAGE_MANAGER_SIZE, 0x34);
        restore(lock);
    }
}
