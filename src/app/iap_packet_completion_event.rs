//! Schedule an iAP packet-completion event.
//!
//! `schedule_iap_packet_completion_event` — original: `FUN_081d7b6c` @
//! **0x081d7b6c**. Raw words establish the true **192-byte** extent: 184 bytes
//! of code through `pop {r4-r8,pc}` at 0x081d7c20, followed by literal words
//! 0x089ccb50 and 0x000002fa; the next function starts at 0x081d7c2c. The
//! code contains **6 plain unconditional `bl` calls**, **0 predicated `bl`
//! calls**, and one runtime-vtable `blx` call.
//!
//! Algorithm: obtain the packet owner mode and command, submit completion, and
//! on success insert a zero-payload pending event. A successful insertion
//! constructs a kind-1 clock, increments context `+0x2fa` with u16 wrapping,
//! reads the clock through vtable slot `+0x0c`, stores milliseconds at `+0x2f4`,
//! and sets `+0x2f8`.
//!
//! # Deliberate deviations
//!
//! `FUN_081d7f14` is unrecovered, so the established volatile
//! `IAP_PACKET_EVENT_SCHEDULE_OPS.complete_packet` seam models it. Target code
//! reads the literal-backed context slot; host tests use a replaceable fixture.

use core::ptr;

use super::iap_packet::iap_packet_owner_mode;
use super::iap_packet_event_schedule::{IapPacketEventScheduleOps, IAP_PACKET_EVENT_SCHEDULE_OPS};
use super::pending_event_insert::{pending_event_insert, PENDING_EVENT_INSERT_OPS};
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;

const IAP_PACKET_COMMAND_HALFWORD: usize = 0x10 / core::mem::size_of::<u16>();
const CLOCK_OBJECT_LEN: usize = 8;

#[repr(C)]
struct PacketEventState {
    _before_timestamp: [u32; 0x2f4 / core::mem::size_of::<u32>()],
    timestamp_ms: u32,
    active: u8,
    _padding: u8,
    sequence: u16,
}

const _: () = assert!(core::mem::offset_of!(PacketEventState, timestamp_ms) == 0x2f4);
const _: () = assert!(core::mem::offset_of!(PacketEventState, active) == 0x2f8);
const _: () = assert!(core::mem::offset_of!(PacketEventState, sequence) == 0x2fa);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn packet_event_context() -> *mut u8 {
    (0x089c_cb50usize as *const *mut u8).read_volatile()
}

#[cfg(not(target_os = "none"))]
static mut HOST_PACKET_EVENT_CONTEXT: *mut u8 = ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn packet_event_context() -> *mut u8 {
    ptr::read_volatile(ptr::addr_of!(HOST_PACKET_EVENT_CONTEXT))
}

/// `schedule_iap_packet_completion_event` — original: `FUN_081d7b6c` @
/// 0x081d7b6c (192 bytes including literals; 6 plain `bl` calls, no predicated
/// `bl` calls, and one vtable `blx`).
///
/// # Safety
///
/// `packet` must contain readable owner and command fields. On successful
/// completion, the 0x089ccb50 context pointer and pending-event queue must be
/// initialized, matching unchecked firmware preconditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.schedule_iap_packet_completion_event")]
pub unsafe extern "C" fn schedule_iap_packet_completion_event(
    _unused_context: *mut u8,
    packet: *mut u8,
    completion_state: u32,
    delay_ms: u32,
) -> u32 {
    let owner_mode = iap_packet_owner_mode(packet.cast_const());
    let command = ptr::read_volatile((packet as *const u16).add(IAP_PACKET_COMMAND_HALFWORD));
    let ops: IapPacketEventScheduleOps = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
    let mut status = (ops.complete_packet)(packet, completion_state);
    if status != 0 {
        return status;
    }

    let context = packet_event_context();
    let state = context.cast::<PacketEventState>();
    let sequence = ptr::read_volatile(ptr::addr_of!((*state).sequence));
    status = pending_event_insert(context, owner_mode, sequence, command, 0, delay_ms);
    if status != 0 {
        return status;
    }

    let mut clock = [0u8; CLOCK_OBJECT_LEN];
    let mut timespec = [0i32; 2];
    clock_source_construct(clock.as_mut_ptr());
    ptr::write_volatile(ptr::addr_of_mut!((*state).sequence), sequence.wrapping_add(1));
    let pending_ops = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
    (pending_ops.clock_read_time)(clock.as_mut_ptr(), timespec.as_mut_ptr());
    ptr::write_volatile(
        ptr::addr_of_mut!((*state).timestamp_ms),
        timespec_to_milliseconds(timespec.as_ptr()) as u32,
    );
    ptr::write_volatile(ptr::addr_of_mut!((*state).active), 1);
    clock_source_destroy(clock.as_mut_ptr().cast());
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::pending_event_insert::{PendingEventInsertOps, ERR_NO_FREE_NODE};
    use crate::app::pending_event_take::PendingEventNode;
    use crate::testing::{hints, try_map_u32_slab, IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK, PENDING_EVENT_INSERT_OPS_TEST_LOCK};
    use parking_lot::Mutex;

    const CONTEXT_LEN: usize = 0x300;
    const NODE_OFFSET: usize = CONTEXT_LEN;
    const PACKET_OFFSET: usize = NODE_OFFSET + 0x20;
    const OWNER_OFFSET: usize = PACKET_OFFSET + 0x40;
    const SLAB_LEN: usize = OWNER_OFFSET + 0x20;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COMPLETION_STATUS: u32 = 0;
    static mut NOW: (i32, i32) = (0, 0);

    unsafe extern "C" fn complete(_packet: *mut u8, _state: u32) -> u32 { COMPLETION_STATUS }
    unsafe extern "C" fn pop(context: *mut u8) -> *mut PendingEventNode {
        let head = context.add(0x18).cast::<u32>();
        let node = (*head as usize) as *mut PendingEventNode;
        if !node.is_null() { *head = (*node).next; }
        node
    }
    unsafe extern "C" fn clock(_clock: *mut u8, out: *mut i32) { out.write(NOW.0); out.add(1).write(NOW.1); }
    unsafe extern "C" fn insert(_context: *mut u8, _node: *mut PendingEventNode) -> u32 { 0 }
    unsafe extern "C" fn rearm(_context: *mut u8) -> u32 { 0 }

    unsafe fn slab() -> Option<*mut u8> {
        static mut SLAB: *mut u8 = ptr::null_mut();
        if SLAB.is_null() { SLAB = try_map_u32_slab(hints::IAP_PACKET_COMPLETION_EVENT, SLAB_LEN)?; }
        Some(SLAB)
    }
    unsafe fn packet(slab: *mut u8, mode: u32, command: u16) -> *mut u8 {
        let packet = slab.add(PACKET_OFFSET);
        let owner = slab.add(OWNER_OFFSET);
        packet.cast::<u32>().write(owner as usize as u32);
        owner.cast::<u32>().add(2).write(mode);
        packet.add(0x10).cast::<u16>().write(command);
        packet
    }

    #[test]
    fn completion_failure_does_not_touch_context() {
        let _test = TEST_LOCK.lock();
        let _completion = IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let previous = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), IapPacketEventScheduleOps { complete_packet: complete });
            COMPLETION_STATUS = 0x55;
            let mut packet = [0u8; 0x20];
            assert_eq!(schedule_iap_packet_completion_event(ptr::null_mut(), packet.as_mut_ptr(), 2, 3), 0x55);
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), previous);
        }
    }

    #[test]
    fn successful_schedule_wraps_sequence_and_stamps_time() {
        let _test = TEST_LOCK.lock();
        let _completion = IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK.lock().unwrap();
        let _pending = PENDING_EVENT_INSERT_OPS_TEST_LOCK.lock().unwrap();
        let Some(slab) = (unsafe { slab() }) else { return };
        unsafe {
            ptr::write_bytes(slab, 0, SLAB_LEN);
            let previous_completion = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
            let previous_pending = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
            let previous_context = ptr::read_volatile(ptr::addr_of!(HOST_PACKET_EVENT_CONTEXT));
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), IapPacketEventScheduleOps { complete_packet: complete });
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), PendingEventInsertOps { pop_free_node: pop, clock_read_time: clock, insert_node: insert, rearm_timer: rearm });
            ptr::write_volatile(ptr::addr_of_mut!(HOST_PACKET_EVENT_CONTEXT), slab);
            COMPLETION_STATUS = 0;
            NOW = (3, 250_000_000);
            (*slab.cast::<PacketEventState>()).sequence = u16::MAX;
            *slab.add(0x18).cast::<u32>() = slab.add(NODE_OFFSET) as usize as u32;
            let packet = packet(slab, 4, 0xbeef);
            assert_eq!(schedule_iap_packet_completion_event(ptr::null_mut(), packet, 1, 200), 0);
            let state = slab.cast::<PacketEventState>();
            assert_eq!((*state).sequence, 0);
            assert_eq!((*state).timestamp_ms, 3250);
            assert_eq!((*state).active, 1);
            ptr::write_volatile(ptr::addr_of_mut!(HOST_PACKET_EVENT_CONTEXT), previous_context);
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), previous_pending);
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), previous_completion);
        }
    }

    #[test]
    fn exhausted_queue_preserves_event_state() {
        let _test = TEST_LOCK.lock();
        let _completion = IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK.lock().unwrap();
        let _pending = PENDING_EVENT_INSERT_OPS_TEST_LOCK.lock().unwrap();
        let Some(slab) = (unsafe { slab() }) else { return };
        unsafe {
            ptr::write_bytes(slab, 0, SLAB_LEN);
            let previous_completion = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
            let previous_pending = ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS));
            let previous_context = ptr::read_volatile(ptr::addr_of!(HOST_PACKET_EVENT_CONTEXT));
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), IapPacketEventScheduleOps { complete_packet: complete });
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), PendingEventInsertOps { pop_free_node: pop, clock_read_time: clock, insert_node: insert, rearm_timer: rearm });
            ptr::write_volatile(ptr::addr_of_mut!(HOST_PACKET_EVENT_CONTEXT), slab);
            COMPLETION_STATUS = 0;
            let state = slab.cast::<PacketEventState>();
            (*state).sequence = 0x1234; (*state).timestamp_ms = 0xfeed_beef; (*state).active = 0x7f;
            assert_eq!(schedule_iap_packet_completion_event(ptr::null_mut(), packet(slab, 2, 0x5678), 0, 1), ERR_NO_FREE_NODE);
            assert_eq!((*state).sequence, 0x1234); assert_eq!((*state).timestamp_ms, 0xfeed_beef); assert_eq!((*state).active, 0x7f);
            ptr::write_volatile(ptr::addr_of_mut!(HOST_PACKET_EVENT_CONTEXT), previous_context);
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), previous_pending);
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), previous_completion);
        }
    }
}
