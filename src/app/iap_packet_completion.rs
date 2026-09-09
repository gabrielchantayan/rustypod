//! Timestamp and complete an iAP packet.
//!
//! `complete_iap_packet_with_timestamp` — original: `FUN_081ac4fc` @
//! **0x081ac4fc**. Raw bytes give a **100-byte** extent: 96 bytes of code
//! through `pop {r4-r6,pc}` @ 0x081ac55c and the literal `0x089ccb68` @
//! 0x081ac560; the separately linked next function begins at 0x081ac564. A
//! complete decode of every ARM `B`/`BL` word in `osos.dec` finds **12 direct
//! `bl` call sites**, all unconditional; no plain `b` or predicated form
//! targets this address.
//!
//! Algorithm: construct a kind-1 clock, read its vtable `+0x0c` timespec,
//! convert it to milliseconds, and write that timestamp to global
//! 0x089ccb68 `+0x18` before setting its `+0x02` active byte. Complete the
//! packet through `FUN_081d7f14`, destroy the clock, and return the completion
//! status. The first and fourth ABI words are stacked by ARM but never read.
//!
//! # Deliberate deviations
//!
//! `FUN_081d7f14` remains unrecovered; this reuses the established volatile
//! `IAP_PACKET_EVENT_SCHEDULE_OPS.complete_packet` seam instead of inventing a
//! callee identity. The dynamic clock read reuses the existing
//! `PENDING_EVENT_INSERT_OPS.clock_read_time` host model; target builds still
//! dispatch through the runtime clock vtable. The target global is represented
//! by a host fixture outside firmware builds.

use core::{mem::MaybeUninit, ptr};

use super::iap_packet_event_schedule::{IapPacketEventScheduleOps, IAP_PACKET_EVENT_SCHEDULE_OPS};
use super::pending_event_insert::PENDING_EVENT_INSERT_OPS;
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;

const CLOCK_OBJECT_LEN: usize = 8;

/// Observed fields of the global state at 0x089ccb68.
#[repr(C)]
struct IapPacketCompletionState {
    _before_completion_active: [u8; 2],
    completion_active: u8,
    _before_completion_timestamp: [u8; 0x18 - 3],
    completion_timestamp_ms: u32,
}

const _: () = assert!(core::mem::offset_of!(IapPacketCompletionState, completion_active) == 0x02);
const _: () = assert!(core::mem::offset_of!(IapPacketCompletionState, completion_timestamp_ms) == 0x18);

#[cfg(target_os = "none")]
const IAP_PACKET_COMPLETION_STATE: *mut IapPacketCompletionState =
    0x089c_cb68 as *mut IapPacketCompletionState;

#[cfg(not(target_os = "none"))]
static mut HOST_IAP_PACKET_COMPLETION_STATE: IapPacketCompletionState = IapPacketCompletionState {
    _before_completion_active: [0; 2],
    completion_active: 0,
    _before_completion_timestamp: [0; 0x18 - 3],
    completion_timestamp_ms: 0,
};

#[inline(always)]
unsafe fn packet_completion_global() -> *mut IapPacketCompletionState {
    #[cfg(target_os = "none")]
    {
        IAP_PACKET_COMPLETION_STATE
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(HOST_IAP_PACKET_COMPLETION_STATE)
    }
}

/// complete_iap_packet_with_timestamp — original: `FUN_081ac4fc` @
/// 0x081ac4fc (100 bytes including one literal; 12 direct unconditional `bl`
/// call sites).
///
/// Stamps the packet-completion state from the kind-1 clock before issuing the
/// packet completion request. Both `_unused_context` and `_unused` preserve
/// the original four-word ABI but have no observable use in the raw body.
///
/// # Safety
///
/// `packet` must be valid for the unrecovered completion implementation. Its
/// runtime global state and clock vtable must be initialized, as required by
/// the unchecked firmware code.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.complete_iap_packet_with_timestamp")]
pub unsafe extern "C" fn complete_iap_packet_with_timestamp(
    _unused_context: *mut u8,
    packet: *mut u8,
    completion_state: u32,
    _unused: u32,
) -> u32 {
    let mut clock = MaybeUninit::<[u8; CLOCK_OBJECT_LEN]>::uninit();
    let mut timespec = MaybeUninit::<[i32; 2]>::uninit();
    let clock_ptr = clock.as_mut_ptr().cast::<u8>();
    let timespec_ptr = timespec.as_mut_ptr().cast::<i32>();
    clock_source_construct(clock_ptr);
    let pending_event_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
    (pending_event_ops.clock_read_time)(clock_ptr, timespec_ptr);
    let convert: unsafe extern "C" fn(*const i32) -> u64 = ptr::read_volatile(
        &(timespec_to_milliseconds as unsafe extern "C" fn(*const i32) -> u64),
    );
    let timestamp_ms = convert(timespec_ptr.cast_const()) as u32;
    let state = packet_completion_global();
    ptr::write_volatile(ptr::addr_of_mut!((*state).completion_timestamp_ms), timestamp_ms);
    ptr::write_volatile(ptr::addr_of_mut!((*state).completion_active), 1);
    let ops: IapPacketEventScheduleOps = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
    let status = (ops.complete_packet)(packet, completion_state);
    clock_source_destroy(clock_ptr.cast());
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::pending_event_insert::{PendingEventInsertOps, PENDING_EVENT_INSERT_OPS};
    use crate::testing::{IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK, PENDING_EVENT_INSERT_OPS_TEST_LOCK};
    use std::sync::MutexGuard;

    static mut COMPLETION_STATUS: u32 = 0;
    static mut COMPLETION_CALLS: u32 = 0;
    static mut LAST_PACKET: *mut u8 = ptr::null_mut();
    static mut LAST_COMPLETION_STATE: u32 = 0;
    static mut CLOCK_READS: u32 = 0;
    static mut NOW_SEC: i32 = 0;
    static mut NOW_NSEC: i32 = 0;

    struct Bench {
        _completion_ops_lock: MutexGuard<'static, ()>,
        _pending_ops_lock: MutexGuard<'static, ()>,
        previous_completion_ops: IapPacketEventScheduleOps,
        previous_pending_ops: PendingEventInsertOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(
                    ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS),
                    self.previous_completion_ops,
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), self.previous_pending_ops);
            }
        }
    }

    unsafe extern "C" fn mock_complete_packet(packet: *mut u8, completion_state: u32) -> u32 {
        let state = packet_completion_global();
        assert_eq!((*state).completion_active, 1, "the active byte precedes completion");
        assert_eq!(
            (*state).completion_timestamp_ms,
            timespec_to_milliseconds([NOW_SEC, NOW_NSEC].as_ptr()) as u32,
            "the timestamp precedes completion",
        );
        COMPLETION_CALLS += 1;
        LAST_PACKET = packet;
        LAST_COMPLETION_STATE = completion_state;
        COMPLETION_STATUS
    }

    unsafe extern "C" fn mock_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
        CLOCK_READS += 1;
        ts_out.write(NOW_SEC);
        ts_out.add(1).write(NOW_NSEC);
    }

    fn bench() -> Bench {
        let completion_ops_lock = IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pending_ops_lock = PENDING_EVENT_INSERT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            COMPLETION_STATUS = 0;
            COMPLETION_CALLS = 0;
            LAST_PACKET = ptr::null_mut();
            LAST_COMPLETION_STATE = 0;
            CLOCK_READS = 0;
            NOW_SEC = 0;
            NOW_NSEC = 0;
            ptr::write_bytes(
                packet_completion_global().cast::<u8>(),
                0,
                core::mem::size_of::<IapPacketCompletionState>(),
            );

            let previous_completion_ops = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS),
                IapPacketEventScheduleOps { complete_packet: mock_complete_packet },
            );
            let previous_pending_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
            let pending_ops = PendingEventInsertOps {
                clock_read_time: mock_clock_read_time,
                ..previous_pending_ops
            };
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), pending_ops);
            Bench {
                _completion_ops_lock: completion_ops_lock,
                _pending_ops_lock: pending_ops_lock,
                previous_completion_ops,
                previous_pending_ops,
            }
        }
    }

    #[test]
    fn timestamps_and_activates_before_successful_completion() {
        let _bench = bench();
        let mut packet = [0u8; 1];
        unsafe {
            NOW_SEC = 4;
            NOW_NSEC = 567_890_123;
        }

        let status = unsafe {
            complete_iap_packet_with_timestamp(
                0x1234usize as *mut u8,
                packet.as_mut_ptr(),
                0xdead_beef,
                0xa5a5_5a5a,
            )
        };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(CLOCK_READS, 1);
            assert_eq!(COMPLETION_CALLS, 1);
            assert_eq!(LAST_PACKET, packet.as_mut_ptr());
            assert_eq!(LAST_COMPLETION_STATE, 0xdead_beef);
            assert_eq!((*packet_completion_global()).completion_timestamp_ms, 4567);
            assert_eq!((*packet_completion_global()).completion_active, 1);
        }
    }

    #[test]
    fn stamps_even_when_completion_reports_an_error() {
        let _bench = bench();
        let mut packet = [0u8; 1];
        unsafe {
            NOW_SEC = 0;
            NOW_NSEC = 999_999;
            COMPLETION_STATUS = 0x55;
        }

        let status = unsafe {
            complete_iap_packet_with_timestamp(ptr::null_mut(), packet.as_mut_ptr(), 7, 0)
        };

        assert_eq!(status, 0x55);
        unsafe {
            assert_eq!(CLOCK_READS, 1);
            assert_eq!(COMPLETION_CALLS, 1);
            assert_eq!(LAST_COMPLETION_STATE, 7);
            assert_eq!((*packet_completion_global()).completion_timestamp_ms, 0, "sub-millisecond nsec truncates");
            assert_eq!((*packet_completion_global()).completion_active, 1);
        }
    }
}
