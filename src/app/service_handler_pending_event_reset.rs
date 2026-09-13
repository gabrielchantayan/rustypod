//! `service_handler_pending_event_reset` — original: `FUN_0818fd78` @
//! **0x0818fd78** (208 bytes of instructions plus the three 4-byte literal
//! pool words at 0x0818fe48..0x0818fe50; next entry 0x0818fe54). Exactly
//! **7 direct `bl` call sites**, all unconditional: 0x0818f0b0, 0x0818f3d0,
//! 0x08190f48, 0x081929a0, 0x08192c84, 0x08193ba8, and 0x08193d9c. Verified
//! by decoding every ARM B/BL immediate in `osos.dec`.
//!
//! The helper resets one of three service-handler pending-event records. It
//! rejects selectors >= 3, locks that record's 28-byte lock cell, and
//! destructs-and-deletes a non-null first-word object (0x08163b18 is a
//! one-word `bx lr` destructor that passes r0 through to `operator_delete`).
//! It then zeroes all 36 record bytes through the IRAM memzero veneer target,
//! and unlocks. It takes and cancels pending events
//! `(selector, wildcard, 0x14)` and `(selector, wildcard, 0x17)` from the
//! session queue, ignoring both statuses. A nonzero `request_lifecycle_state`
//! obtains the service-manager singleton and requests lifecycle state 0 for
//! the selector.
//!
//! # Deliberate deviations
//!
//! The retail calls 0x08037db8, an IRAM veneer for the already ported
//! `memzero_aligned`; this port loads that callee through a volatile function
//! pointer, preserving a call and preventing LLVM from recognizing a builtin
//! clear. `FUN_08138c80` is not ported, so it remains behind the narrowly
//! scoped lifecycle-request seam: target builds call its verified entry,
//! while host tests record its arguments. The preceding empty destructor
//! 0x08163b18 is represented by its observable tail call to the already
//! ported `operator_delete`. Lock/unlock and pending-event take call their
//! existing Rust ports directly.

use crate::app::pending_event_take::{pending_event_take, WILDCARD_TAG};
use crate::app::service_manager::service_manager_instance_veneer;
use crate::heap::veneers::{heap_panic, operator_delete};
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use crate::libc::memzero::memzero_aligned;
use core::ptr;

const RECORD_COUNT: i32 = 3;
const RECORD_WORDS: usize = 9;
const LOCK_WORDS: usize = 7;
const EVENT_TAG_FIRST: u16 = 0x14;
const EVENT_TAG_SECOND: u16 = 0x17;

type PendingEventRecord = [u32; RECORD_WORDS];
type PendingEventLock = [u32; LOCK_WORDS];
type MemzeroAligned = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
type RequestLifecycleState = unsafe extern "C" fn(*mut u8, i32, i32) -> u32;

#[cfg(target_os = "none")]
unsafe fn records() -> *mut PendingEventRecord {
    0x08a2_55e4 as *mut PendingEventRecord
}

#[cfg(not(target_os = "none"))]
static mut HOST_RECORDS: [PendingEventRecord; RECORD_COUNT as usize] = [[0; RECORD_WORDS]; RECORD_COUNT as usize];

#[cfg(not(target_os = "none"))]
unsafe fn records() -> *mut PendingEventRecord {
    core::ptr::addr_of_mut!(HOST_RECORDS).cast()
}

#[cfg(target_os = "none")]
unsafe fn locks() -> *mut PendingEventLock {
    0x08a2_5650 as *mut PendingEventLock
}

#[cfg(not(target_os = "none"))]
static mut HOST_LOCKS: [PendingEventLock; RECORD_COUNT as usize] = [[0; LOCK_WORDS]; RECORD_COUNT as usize];

#[cfg(not(target_os = "none"))]
unsafe fn locks() -> *mut PendingEventLock {
    core::ptr::addr_of_mut!(HOST_LOCKS).cast()
}

/// Stable indirection for the already ported IRAM veneer target. A volatile
/// load prevents LLVM from re-lowering the clear into an ARM runtime builtin.
static MEMZERO_ALIGNED: MemzeroAligned = memzero_aligned;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_request_lifecycle_state(
    manager: *mut u8,
    selector: i32,
    state: i32,
) -> u32 {
    let request: RequestLifecycleState = core::mem::transmute(0x0813_8c80usize);
    request(manager, selector, state)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_request_lifecycle_state(
    _manager: *mut u8,
    _selector: i32,
    _state: i32,
) -> u32 {
    0
}

#[derive(Clone, Copy)]
struct ServiceHandlerPendingEventResetOps {
    request_lifecycle_state: RequestLifecycleState,
}

static mut SERVICE_HANDLER_PENDING_EVENT_RESET_OPS: ServiceHandlerPendingEventResetOps =
    ServiceHandlerPendingEventResetOps {
        request_lifecycle_state: firmware_request_lifecycle_state,
    };

#[inline(always)]
unsafe fn reset_ops() -> ServiceHandlerPendingEventResetOps {
    ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_PENDING_EVENT_RESET_OPS))
}

/// service_handler_pending_event_reset — original: `FUN_0818fd78` @
/// **0x0818fd78** (208 instruction bytes; 7 direct unconditional `bl` call
/// sites, binary-verified — see module header).
///
/// Clears the selector's pending-event record, consumes its two reset event
/// kinds, and optionally requests lifecycle state zero from the singleton.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_pending_event_reset(
    session: *mut u8,
    selector: i32,
    request_lifecycle_state: u32,
) {
    if selector >= RECORD_COUNT {
        heap_panic();
    }

    let record = records().wrapping_offset(selector as isize);
    let lock = locks().wrapping_offset(selector as isize).cast::<PosixMutex>();
    posix_mutex_lock(lock);
    let object = ptr::read(record.cast::<u32>()) as usize as *mut u8;
    if !object.is_null() {
        // FUN_08163b18 is exactly `bx lr`, so r0 reaches operator_delete
        // unchanged in the retail `bl; bl` pair.
        operator_delete(object);
    }

    let clear = ptr::read_volatile(ptr::addr_of!(MEMZERO_ALIGNED));
    clear(record.cast(), core::mem::size_of::<PendingEventRecord>());
    posix_mutex_unlock(lock);

    let mut wildcard = WILDCARD_TAG;
    let mut event_tag = EVENT_TAG_FIRST;
    pending_event_take(session, selector as u32, &mut wildcard, &mut event_tag, ptr::null_mut());

    wildcard = WILDCARD_TAG;
    event_tag = EVENT_TAG_SECOND;
    pending_event_take(session, selector as u32, &mut wildcard, &mut event_tag, ptr::null_mut());

    if request_lifecycle_state != 0 {
        let manager = service_manager_instance_veneer();
        (reset_ops().request_lifecycle_state)(manager, selector, 0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::pending_event_take::{PendingEventTakeOps, DEFAULT_PENDING_EVENT_TAKE_OPS, PENDING_EVENT_TAKE_OPS};
    use crate::app::service_manager::{SERVICE_MANAGER_INSTANCE, SERVICE_MANAGER_INSTANCE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, PENDING_EVENT_TAKE_OPS_TEST_LOCK};
    use std::sync::Mutex;
    use std::vec::Vec;

    static RESET_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TAKE_CALLS: Vec<(u32, u16, u16)> = Vec::new();
    static mut LIFECYCLE_CALLS: Vec<(*mut u8, i32, i32)> = Vec::new();

    unsafe extern "C" fn record_take(
        _session: *mut u8,
        key: u32,
        tag_a: u16,
        tag_b: u16,
    ) -> *mut u32 {
        TAKE_CALLS.push((key, tag_a, tag_b));
        ptr::null_mut()
    }

    unsafe extern "C" fn no_release(_session: *mut u8, _node: *mut crate::app::pending_event_take::PendingEventNode) -> u32 {
        0
    }

    unsafe extern "C" fn no_rearm(_session: *mut u8) -> u32 {
        0
    }

    unsafe extern "C" fn record_lifecycle(manager: *mut u8, selector: i32, state: i32) -> u32 {
        LIFECYCLE_CALLS.push((manager, selector, state));
        0
    }

    unsafe fn session() -> Option<*mut u8> {
        static mut SESSION: *mut u8 = ptr::null_mut();
        if SESSION.is_null() {
            SESSION = match try_map_u32_slab(hints::SERVICE_HANDLER_PENDING_EVENT_RESET, 0x400) {
                Some(session) => session,
                None => {
                    note_missing_u32_fixture("app::service_handler_pending_event_reset");
                    return None;
                }
            };
        }
        ptr::write_bytes(SESSION, 0, 0x400);
        Some(SESSION)
    }

    struct Fixture {
        _reset_ops: std::sync::MutexGuard<'static, ()>,
        _take_ops: std::sync::MutexGuard<'static, ()>,
        _instance: std::sync::MutexGuard<'static, ()>,
        old_take_ops: PendingEventTakeOps,
        old_reset_ops: ServiceHandlerPendingEventResetOps,
    }

    impl Fixture {
        unsafe fn new() -> Self {
            let reset_ops = RESET_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let take_ops = PENDING_EVENT_TAKE_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let instance = SERVICE_MANAGER_INSTANCE_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let old_take_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_TAKE_OPS));
            let old_reset_ops = ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_PENDING_EVENT_RESET_OPS));
            PENDING_EVENT_TAKE_OPS = PendingEventTakeOps {
                find_link: record_take,
                release_node: no_release,
                rearm_timer: no_rearm,
            };
            SERVICE_HANDLER_PENDING_EVENT_RESET_OPS = ServiceHandlerPendingEventResetOps {
                request_lifecycle_state: record_lifecycle,
            };
            TAKE_CALLS.clear();
            LIFECYCLE_CALLS.clear();
            HOST_RECORDS = [[0; RECORD_WORDS]; RECORD_COUNT as usize];
            HOST_LOCKS = [[0; LOCK_WORDS]; RECORD_COUNT as usize];
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
            Self {
                _reset_ops: reset_ops,
                _take_ops: take_ops,
                _instance: instance,
                old_take_ops,
                old_reset_ops,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                PENDING_EVENT_TAKE_OPS = self.old_take_ops;
                SERVICE_HANDLER_PENDING_EVENT_RESET_OPS = self.old_reset_ops;
                ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), ptr::null_mut());
            }
        }
    }

    #[test]
    fn clears_only_the_selected_record_and_drains_both_reset_event_kinds() {
        let _fixture = unsafe { Fixture::new() };
        let Some(session) = (unsafe { session() }) else { return };
        unsafe {
            HOST_RECORDS = [[0x1111_1111; RECORD_WORDS], [0x2222_2222; RECORD_WORDS], [0x3333_3333; RECORD_WORDS]];
            HOST_RECORDS[1][0] = 0;

            service_handler_pending_event_reset(session, 1, 0);

            assert_eq!(HOST_RECORDS[0], [0x1111_1111; RECORD_WORDS]);
            assert_eq!(HOST_RECORDS[1], [0; RECORD_WORDS]);
            assert_eq!(HOST_RECORDS[2], [0x3333_3333; RECORD_WORDS]);
            assert_eq!(TAKE_CALLS, [(1, WILDCARD_TAG, EVENT_TAG_FIRST), (1, WILDCARD_TAG, EVENT_TAG_SECOND)]);
            assert_eq!(HOST_LOCKS[1][1], 0, "the per-record mutex is released");
            assert!(LIFECYCLE_CALLS.is_empty(), "zero request flag skips lifecycle state request");
        }
    }

    #[test]
    fn nonzero_request_flag_forwards_the_singleton_and_state_zero() {
        let _fixture = unsafe { Fixture::new() };
        let Some(session) = (unsafe { session() }) else { return };
        let mut manager = [0u8; 0xe8];
        unsafe {
            HOST_RECORDS[2][0] = 0;
            ptr::write_volatile(ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE), manager.as_mut_ptr());

            service_handler_pending_event_reset(session, 2, 0xffff_ffff);

            assert_eq!(
                LIFECYCLE_CALLS,
                [(manager.as_mut_ptr(), 2, 0)],
                "all nonzero flags select the service-manager lifecycle request"
            );
            assert_eq!(TAKE_CALLS, [(2, WILDCARD_TAG, EVENT_TAG_FIRST), (2, WILDCARD_TAG, EVENT_TAG_SECOND)]);
        }
    }

    #[test]
    fn default_pending_take_configuration_is_restored_after_fixture_drop() {
        let fixture = unsafe { Fixture::new() };
        drop(fixture);
        let _take_guard = PENDING_EVENT_TAKE_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let restored = unsafe { ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_TAKE_OPS)) };
        assert_eq!(restored.find_link as usize, DEFAULT_PENDING_EVENT_TAKE_OPS.find_link as usize);
    }
}
