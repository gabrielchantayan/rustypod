//! Schedule an iAP packet event through the active service-handler context.
//!
//! `schedule_iap_packet_event` — original: `FUN_08195214` @ **0x08195214**.
//! Raw bytes give a **196-byte** extent: 188 bytes of code through `pop
//! {r4-r8,pc}` @ 0x081952cc plus literals 0x089ccb5c and 0x000002fa @
//! 0x081952d0..0x081952d7; the separately linked next function begins at
//! 0x081952d8. A complete decode of every ARM `B`/`BL` word in `osos.dec`
//! finds **13 direct `bl` call sites**, all unconditional; no predicated form
//! targets this address.
//!
//! Algorithm: get the packet owner mode and command tag, complete the packet
//! through 0x081d7f14, then enqueue `{key=owner_mode, tag_a=context+0x2fa,
//! tag_b=packet+0x10, payload=0, delta_ms}` into the active context's pending
//! event queue. Only a successful enqueue increments the u16 tag sequence,
//! records a fresh clock timestamp at `+0x2f4`, and sets the byte at `+0x2f8`.
//!
//! # Deliberate deviations
//!
//! `FUN_081d7f14` is not ported. Its decoded body writes the packet's `+0x1a`
//! completion flag and submits the packet to an internal worker, but the
//! worker's protocol is unrecovered. It therefore remains a volatile
//! target/host dispatch seam rather than acquiring an invented identity. The
//! active-context global at 0x089ccb5c and all other direct callees reuse their
//! existing ports.

use core::ptr;

use super::active_service_handler_readiness::active_service_handler_context_raw;
use super::iap_packet::iap_packet_owner_mode;
use super::pending_event_insert::{pending_event_insert, PENDING_EVENT_INSERT_OPS};
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;

/// Packet command at +0x10, expressed as an aligned halfword index rather
/// than a byte offset. The iAP packet has target-width pointer words before
/// this field, so a host-native Rust pointer struct would not have its layout.
const IAP_PACKET_COMMAND_HALFWORD: usize = 0x10 / core::mem::size_of::<u16>();
const CLOCK_OBJECT_LEN: usize = 8;

/// The observed tail of the active service-handler context. All preceding
/// fields are target words, so this representation has the same offsets on
/// the 32-bit firmware and the host.
#[repr(C)]
struct ActiveServiceHandlerEventState {
    _before_pending_event_timestamp: [u32; 0x2f4 / core::mem::size_of::<u32>()],
    pending_event_timestamp_ms: u32,
    pending_event_active: u8,
    _padding_after_pending_event_active: u8,
    pending_event_sequence: u16,
}

const _: () = assert!(core::mem::offset_of!(ActiveServiceHandlerEventState, pending_event_timestamp_ms) == 0x2f4);
const _: () = assert!(core::mem::offset_of!(ActiveServiceHandlerEventState, pending_event_active) == 0x2f8);
const _: () = assert!(core::mem::offset_of!(ActiveServiceHandlerEventState, pending_event_sequence) == 0x2fa);

/// Dispatch for unported packet completion `FUN_081d7f14`.
#[derive(Clone, Copy)]
pub struct IapPacketEventScheduleOps {
    /// Writes the packet completion state and submits its internal work.
    /// Returns zero when the packet was accepted.
    pub complete_packet: unsafe extern "C" fn(packet: *mut u8, completion_state: u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_complete_packet(packet: *mut u8, completion_state: u32) -> u32 {
    let f: unsafe extern "C" fn(*mut u8, u32) -> u32 = core::mem::transmute(0x081d_7f14usize);
    f(packet, completion_state)
}

/// Host default is inert and fails with the callee's observed global-not-ready
/// status (the `mov r0,#10` path). Tests install a recording model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_complete_packet(_packet: *mut u8, _completion_state: u32) -> u32 {
    10
}

/// Target ROM dispatch or the documented inert host default.
pub const DEFAULT_IAP_PACKET_EVENT_SCHEDULE_OPS: IapPacketEventScheduleOps = IapPacketEventScheduleOps {
    complete_packet: firmware_complete_packet,
};

/// Read volatile below so LLVM retains the target call instead of folding the
/// host default into this wrapper.
pub static mut IAP_PACKET_EVENT_SCHEDULE_OPS: IapPacketEventScheduleOps =
    DEFAULT_IAP_PACKET_EVENT_SCHEDULE_OPS;

#[inline(always)]
fn iap_packet_event_schedule_ops() -> IapPacketEventScheduleOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS)) }
}

/// schedule_iap_packet_event — original: `FUN_08195214` @ 0x08195214 (196
/// bytes including two literals; 13 direct unconditional `bl` call sites).
///
/// Completes `packet`, schedules a zero-payload event in the active context,
/// then records the clock and marks that context active when scheduling
/// succeeded. The first ABI word is preserved but unused: raw ARM stacks it,
/// then overwrites that local with zero before its only use as the clock's
/// `{sec,nsec}` output buffer.
///
/// # Safety
///
/// `packet` must address an iAP packet with a readable command halfword. On a
/// successful completion, the global 0x089ccb5c must contain an initialized
/// active context whose queue and event-state tail are valid. These are the
/// unguarded firmware preconditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.schedule_iap_packet_event")]
pub unsafe extern "C" fn schedule_iap_packet_event(
    _unused_context: *mut u8,
    packet: *mut u8,
    completion_state: u32,
    delay_ms: u32,
) -> u32 {
    let owner_mode = iap_packet_owner_mode(packet.cast_const());
    let command = ptr::read_volatile((packet as *const u16).add(IAP_PACKET_COMMAND_HALFWORD));
    let ops = iap_packet_event_schedule_ops();
    let mut status = (ops.complete_packet)(packet, completion_state);
    if status != 0 {
        return status;
    }

    let context = active_service_handler_context_raw();
    let event_state = context.cast::<ActiveServiceHandlerEventState>();
    let sequence = ptr::read_volatile(ptr::addr_of!((*event_state).pending_event_sequence));
    status = pending_event_insert(context, owner_mode, sequence, command, 0, delay_ms);
    if status != 0 {
        return status;
    }

    let mut clock = [0u8; CLOCK_OBJECT_LEN];
    let mut timespec = [0i32; 2];
    clock_source_construct(clock.as_mut_ptr());
    ptr::write_volatile(
        ptr::addr_of_mut!((*event_state).pending_event_sequence),
        sequence.wrapping_add(1),
    );
    let pending_event_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
    (pending_event_ops.clock_read_time)(clock.as_mut_ptr(), timespec.as_mut_ptr());
    let timestamp_ms = timespec_to_milliseconds(timespec.as_ptr()) as u32;
    ptr::write_volatile(
        ptr::addr_of_mut!((*event_state).pending_event_timestamp_ms),
        timestamp_ms,
    );
    ptr::write_volatile(ptr::addr_of_mut!((*event_state).pending_event_active), 1);
    clock_source_destroy(clock.as_mut_ptr().cast());
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::active_service_handler_readiness::replace_active_service_handler_context;
    use crate::app::pending_event_insert::{PendingEventInsertOps, PENDING_EVENT_INSERT_OPS};
    use crate::app::pending_event_take::PendingEventNode;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab,
        ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK, PENDING_EVENT_INSERT_OPS_TEST_LOCK,
    };
    use std::sync::{Mutex, MutexGuard};

    const CONTEXT_LEN: usize = 0x300;
    const NODE_OFFSET: usize = CONTEXT_LEN;
    const PACKET_OFFSET: usize = NODE_OFFSET + 0x20;
    const OWNER_OFFSET: usize = PACKET_OFFSET + 0x40;
    const SLAB_LEN: usize = OWNER_OFFSET + 0x20;
    const FREE_LIST_WORD: usize = 0x18 / core::mem::size_of::<u32>();
    const OWNER_MODE_WORD: usize = 0x08 / core::mem::size_of::<u32>();

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COMPLETION_STATUS: u32 = 0;
    static mut COMPLETION_CALLS: u32 = 0;
    static mut LAST_PACKET: *mut u8 = ptr::null_mut();
    static mut LAST_COMPLETION_STATE: u32 = 0;
    static mut POP_CALLS: u32 = 0;
    static mut INSERT_CALLS: u32 = 0;
    static mut REARM_CALLS: u32 = 0;
    static mut LAST_NODE: *mut PendingEventNode = ptr::null_mut();
    static mut NOW_SEC: i32 = 0;
    static mut NOW_NSEC: i32 = 0;

    struct Bench {
        _test_lock: MutexGuard<'static, ()>,
        _context_lock: MutexGuard<'static, ()>,
        _pending_ops_lock: MutexGuard<'static, ()>,
        previous_completion_ops: IapPacketEventScheduleOps,
        previous_pending_ops: PendingEventInsertOps,
        previous_context: *mut u8,
        slab: *mut u8,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(
                    ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS),
                    self.previous_completion_ops,
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS),
                    self.previous_pending_ops,
                );
                replace_active_service_handler_context(self.previous_context);
            }
        }
    }

    unsafe fn slab() -> *mut u8 {
        static mut SLAB: *mut u8 = ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::IAP_PACKET_EVENT_SCHEDULE, SLAB_LEN) {
                Some(mapped) => SLAB = mapped,
                None => {
                    note_missing_u32_fixture("app::iap_packet_event_schedule");
                }
            }
        }
        SLAB
    }

    unsafe extern "C" fn mock_complete_packet(packet: *mut u8, completion_state: u32) -> u32 {
        COMPLETION_CALLS += 1;
        LAST_PACKET = packet;
        LAST_COMPLETION_STATE = completion_state;
        COMPLETION_STATUS
    }

    unsafe extern "C" fn mock_pop_free_node(this: *mut u8) -> *mut PendingEventNode {
        assert_eq!(this, slab());
        POP_CALLS += 1;
        let head = this.cast::<u32>().add(FREE_LIST_WORD);
        let node = *head as usize as *mut PendingEventNode;
        if !node.is_null() {
            *head = (*node).next;
        }
        node
    }

    unsafe extern "C" fn mock_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
        ts_out.write(NOW_SEC);
        ts_out.add(1).write(NOW_NSEC);
    }

    unsafe extern "C" fn mock_insert_node(this: *mut u8, node: *mut PendingEventNode) -> u32 {
        assert_eq!(this, slab());
        INSERT_CALLS += 1;
        LAST_NODE = node;
        0
    }

    unsafe extern "C" fn mock_rearm_timer(this: *mut u8) -> u32 {
        assert_eq!(this, slab());
        REARM_CALLS += 1;
        0
    }


    fn bench() -> Option<Bench> {
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let context_lock = ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pending_ops_lock = PENDING_EVENT_INSERT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let slab = unsafe { slab() };
        if slab.is_null() {
            return None;
        }

        unsafe {
            ptr::write_bytes(slab, 0, SLAB_LEN);
            COMPLETION_STATUS = 0;
            COMPLETION_CALLS = 0;
            LAST_PACKET = ptr::null_mut();
            LAST_COMPLETION_STATE = 0;
            POP_CALLS = 0;
            INSERT_CALLS = 0;
            REARM_CALLS = 0;
            LAST_NODE = ptr::null_mut();
            NOW_SEC = 0;
            NOW_NSEC = 0;

            let previous_completion_ops = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS),
                IapPacketEventScheduleOps { complete_packet: mock_complete_packet },
            );
            let previous_pending_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS),
                PendingEventInsertOps {
                    pop_free_node: mock_pop_free_node,
                    clock_read_time: mock_clock_read_time,
                    insert_node: mock_insert_node,
                    rearm_timer: mock_rearm_timer,
                },
            );
            let previous_context = replace_active_service_handler_context(slab);
            Some(Bench {
                _test_lock: test_lock,
                _context_lock: context_lock,
                _pending_ops_lock: pending_ops_lock,
                previous_completion_ops,
                previous_pending_ops,
                previous_context,
                slab,
            })
        }
    }

    unsafe fn packet(bench: &Bench) -> *mut u8 {
        bench.slab.add(PACKET_OFFSET)
    }

    unsafe fn event_state(bench: &Bench) -> *mut ActiveServiceHandlerEventState {
        bench.slab.cast()
    }

    unsafe fn node(bench: &Bench) -> *mut PendingEventNode {
        bench.slab.add(NODE_OFFSET).cast()
    }

    unsafe fn prepare_packet(bench: &Bench, mode: u32, command: u16) -> *mut u8 {
        let packet = packet(bench);
        let owner = bench.slab.add(OWNER_OFFSET);
        packet.cast::<u32>().write((owner as usize) as u32);
        owner.cast::<u32>().add(OWNER_MODE_WORD).write(mode);
        packet.cast::<u16>().add(IAP_PACKET_COMMAND_HALFWORD).write(command);
        packet
    }

    #[test]
    fn completion_failure_skips_pending_event_state() {
        let Some(bench) = bench() else { return };
        let packet = unsafe { prepare_packet(&bench, 0, 0x1234) };
        unsafe { COMPLETION_STATUS = 0x55; }

        let status = unsafe { schedule_iap_packet_event(ptr::null_mut(), packet, 7, 200) };

        assert_eq!(status, 0x55);
        unsafe {
            assert_eq!(COMPLETION_CALLS, 1);
            assert_eq!(LAST_PACKET, packet);
            assert_eq!(LAST_COMPLETION_STATE, 7);
            assert_eq!(POP_CALLS, 0);
            assert_eq!(INSERT_CALLS, 0);
            assert_eq!(REARM_CALLS, 0);
        }
    }

    #[test]
    fn scheduled_event_uses_preincrement_sequence_and_updates_context_clock() {
        let Some(bench) = bench() else { return };
        let packet = unsafe { prepare_packet(&bench, 4, 0xbeef) };
        unsafe {
            (*event_state(&bench)).pending_event_sequence = u16::MAX;
            (*event_state(&bench)).pending_event_timestamp_ms = 99;
            (*event_state(&bench)).pending_event_active = 0;
            bench.slab.cast::<u32>().add(FREE_LIST_WORD).write(node(&bench) as usize as u32);
            NOW_SEC = 3;
            NOW_NSEC = 250_000_000;
        }

        let status = unsafe { schedule_iap_packet_event(ptr::null_mut(), packet, 1, 200) };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(COMPLETION_CALLS, 1);
            assert_eq!(LAST_COMPLETION_STATE, 1);
            assert_eq!(POP_CALLS, 1);
            assert_eq!(INSERT_CALLS, 1);
            assert_eq!(REARM_CALLS, 1);
            assert_eq!(LAST_NODE, node(&bench));
            assert_eq!((*node(&bench)).key, 4);
            assert_eq!((*node(&bench)).tag_a, u16::MAX);
            assert_eq!((*node(&bench)).tag_b, 0xbeef);
            assert_eq!((*node(&bench)).payload, 0);
            assert_eq!((*node(&bench)).deadline_ms, 3450);
            assert_eq!((*event_state(&bench)).pending_event_sequence, 0);
            assert_eq!((*event_state(&bench)).pending_event_timestamp_ms, 3250);
            assert_eq!((*event_state(&bench)).pending_event_active, 1);
        }
    }

    #[test]
    fn exhausted_queue_leaves_event_clock_and_sequence_untouched() {
        let Some(bench) = bench() else { return };
        let packet = unsafe { prepare_packet(&bench, 2, 0x5678) };
        unsafe {
            (*event_state(&bench)).pending_event_sequence = 0x1234;
            (*event_state(&bench)).pending_event_timestamp_ms = 0xfeed_beef;
            (*event_state(&bench)).pending_event_active = 0x7f;
        }

        let status = unsafe { schedule_iap_packet_event(ptr::null_mut(), packet, 0, 1) };

        assert_eq!(status, super::super::pending_event_insert::ERR_NO_FREE_NODE);
        unsafe {
            assert_eq!(COMPLETION_CALLS, 1);
            assert_eq!(POP_CALLS, 1);
            assert_eq!(INSERT_CALLS, 0);
            assert_eq!(REARM_CALLS, 1);
            assert_eq!((*event_state(&bench)).pending_event_sequence, 0x1234);
            assert_eq!((*event_state(&bench)).pending_event_timestamp_ms, 0xfeed_beef);
            assert_eq!((*event_state(&bench)).pending_event_active, 0x7f);
        }
    }
}
