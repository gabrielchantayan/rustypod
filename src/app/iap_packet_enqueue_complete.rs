//! Enqueue a pending iAP event before submitting packet completion.
//!
//! `iap_packet_enqueue_complete` — `FUN_08139be8` @ **0x08139be8**.
//! True extent **212 bytes**, 0x08139be8..0x08139cbc: 208 code bytes and
//! the 0xffff literal at 0x08139cb8; next function starts with push at
//! 0x08139cbc. Raw ARM word decoding finds **2 plain inbound BLs**, zero
//! predicated inbound BLs, and **4 plain outbound BLs**, zero predicated.
//! Read owner mode and command, insert a zero-payload event with the supplied
//! delay and optional sequence (NULL means wildcard). An insert failure is
//! returned without completing the packet. Completion failure cancels the
//! matching event and returns the cancellation status, not completion status.
//! Success advances a non-wildcard sequence, skipping 0xffff by wrapping to 0.
//!
//! Deliberate deviations: ported owner/insert/take callees are called directly;
//! unrecovered 0x081d7f14 reuses IAP_PACKET_EVENT_SCHEDULE_OPS. ARM's word
//! stack slots for tags become u16 locals (only their low halfwords are read).
//! Ghidra's void return is corrected: raw r0 holds insert/completion/take
//! status at the shared epilogue, and caller 0x08190c30 consumes it.

use core::ptr;
use super::iap_packet::iap_packet_owner_mode;
use super::iap_packet_event_schedule::IAP_PACKET_EVENT_SCHEDULE_OPS;
use super::pending_event_insert::pending_event_insert;
use super::pending_event_take::{pending_event_take, WILDCARD_TAG};

/// # Safety
/// `context` must contain an initialized pending-event queue; `packet` must
/// have readable target-width owner and command fields. A non-NULL sequence
/// must be readable/writable and valid across packet completion.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_enqueue_complete(
    context: *mut u8,
    packet: *mut u8,
    delay_ms: u32,
    sequence: *mut u16,
    completion_state: u32,
) -> u32 {
    let key = iap_packet_owner_mode(packet.cast_const());
    let mut command = ptr::read_volatile(packet.cast::<u16>().add(8));
    let mut tag = if sequence.is_null() { WILDCARD_TAG } else { ptr::read_volatile(sequence) };
    let status = pending_event_insert(context, key, tag, command, 0, delay_ms);
    if status != 0 { return status; }
    let ops = ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS));
    let status = (ops.complete_packet)(packet, completion_state);
    if status != 0 {
        return pending_event_take(context, key, &mut tag, &mut command, ptr::null_mut());
    }
    if !sequence.is_null() && tag != WILDCARD_TAG {
        let next = tag.wrapping_add(1);
        ptr::write_volatile(sequence, if next == WILDCARD_TAG { 0 } else { next });
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::iap_packet_event_schedule::IapPacketEventScheduleOps;
    use super::super::pending_event_insert::{PendingEventInsertOps, PENDING_EVENT_INSERT_OPS};
    use super::super::pending_event_take::{PendingEventNode, PendingEventTakeOps, PENDING_EVENT_TAKE_OPS};
    use crate::testing::{hints, try_map_u32_slab, IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK,
        PENDING_EVENT_INSERT_OPS_TEST_LOCK, PENDING_EVENT_TAKE_OPS_TEST_LOCK};

    static mut COMPLETE_STATUS: u32 = 0;
    static mut LIVE: bool = false;
    static mut NODE: *mut PendingEventNode = ptr::null_mut();
    static mut COMPLETIONS: u32 = 0;
    static mut MISS: bool = false;

    unsafe extern "C" fn pop(context: *mut u8) -> *mut PendingEventNode {
        let head = context.add(0x18).cast::<u32>();
        let node = *head as usize as *mut PendingEventNode;
        if !node.is_null() { *head = (*node).next; }
        node
    }
    unsafe extern "C" fn clock(_: *mut u8, out: *mut i32) { out.write(0); out.add(1).write(0); }
    unsafe extern "C" fn insert(_: *mut u8, node: *mut PendingEventNode) -> u32 {
        NODE = node; LIVE = true; 0
    }
    unsafe extern "C" fn rearm(_: *mut u8) -> u32 { 0 }
    unsafe extern "C" fn complete(_: *mut u8, state: u32) -> u32 {
        assert!(LIVE); assert_eq!(state, 7); COMPLETIONS += 1; COMPLETE_STATUS
    }
    unsafe extern "C" fn find(context: *mut u8, key: u32, a: u32, b: u32) -> *mut u32 {
        let (a, b) = (a as u16, b as u16);
        if MISS || !LIVE || (*NODE).key != key || (a != WILDCARD_TAG && (*NODE).tag_a != a)
            || (b != WILDCARD_TAG && (*NODE).tag_b != b) { return ptr::null_mut(); }
        let link = context.cast::<u32>();
        link.write(NODE as usize as u32); link
    }
    unsafe extern "C" fn release(context: *mut u8, node: *mut PendingEventNode) -> u32 {
        LIVE = false; context.cast::<u32>().write(0);
        context.add(0x18).cast::<u32>().write(node as usize as u32); 0
    }
    struct Restore(PendingEventInsertOps, PendingEventTakeOps, IapPacketEventScheduleOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_INSERT_OPS), self.0);
            ptr::write_volatile(ptr::addr_of_mut!(PENDING_EVENT_TAKE_OPS), self.1);
            ptr::write_volatile(ptr::addr_of_mut!(IAP_PACKET_EVENT_SCHEDULE_OPS), self.2);
        } }
    }

    #[test]
    fn queue_transaction_and_every_sequence_boundary() {
        let _insert = PENDING_EVENT_INSERT_OPS_TEST_LOCK.lock().unwrap();
        let _take = PENDING_EVENT_TAKE_OPS_TEST_LOCK.lock().unwrap();
        let _complete = IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let slab = try_map_u32_slab(hints::IAP_PACKET_ENQUEUE_COMPLETE, 0x400).expect("u32 fixture");
            ptr::write_bytes(slab, 0, 0x400);
            let node = slab.add(0x300).cast::<PendingEventNode>();
            let packet = slab.add(0x340);
            let owner = slab.add(0x380);
            packet.cast::<u32>().write(owner as usize as u32);
            owner.cast::<u32>().add(2).write(4);
            packet.cast::<u16>().add(8).write(0x14);
            let _restore = Restore(ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_INSERT_OPS)),
                ptr::read_volatile(ptr::addr_of!(PENDING_EVENT_TAKE_OPS)),
                ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_SCHEDULE_OPS)));
            PENDING_EVENT_INSERT_OPS = PendingEventInsertOps { pop_free_node: pop, clock_read_time: clock,
                insert_node: insert, rearm_timer: rearm };
            PENDING_EVENT_TAKE_OPS = PendingEventTakeOps { find_link: find, release_node: release, rearm_timer: rearm };
            IAP_PACKET_EVENT_SCHEDULE_OPS = IapPacketEventScheduleOps { complete_packet: complete };
            COMPLETE_STATUS = 0; COMPLETIONS = 0; LIVE = false; MISS = false;
            let mut sequence = 19;
            assert_eq!(iap_packet_enqueue_complete(slab, packet, 123, &mut sequence, 7), 12);
            assert_eq!(sequence, 19); assert_eq!(COMPLETIONS, 0); assert!(!LIVE);
            for initial in 0..=u16::MAX {
                (*node).next = 0;
                slab.add(0x18).cast::<u32>().write(node as usize as u32);
                sequence = initial;
                assert_eq!(iap_packet_enqueue_complete(slab, packet, 123, &mut sequence, 7), 0);
                let expected = match initial { 0xfffe => 0, 0xffff => 0xffff, _ => initial + 1 };
                assert_eq!(sequence, expected);
                assert_eq!(((*node).key, (*node).tag_a, (*node).tag_b, (*node).payload, (*node).deadline_ms),
                    (4, initial, 0x14, 0, 123));
            }
            for initial in [0, 0xfffe, 0xffff] {
                slab.add(0x18).cast::<u32>().write(node as usize as u32);
                sequence = initial; COMPLETE_STATUS = 10;
                assert_eq!(iap_packet_enqueue_complete(slab, packet, 1, &mut sequence, 7), 0);
                assert_eq!(sequence, initial); assert!(!LIVE);
                assert_eq!(*slab.add(0x18).cast::<u32>(), node as usize as u32);
            }
            slab.add(0x18).cast::<u32>().write(node as usize as u32);
            MISS = true; sequence = 21;
            assert_eq!(iap_packet_enqueue_complete(slab, packet, 1, &mut sequence, 7), 0x52);
            assert_eq!(sequence, 21); assert!(LIVE);
            MISS = false;
            for completion in [0, 10] {
                slab.add(0x18).cast::<u32>().write(node as usize as u32);
                COMPLETE_STATUS = completion;
                assert_eq!(iap_packet_enqueue_complete(slab, packet, 1, ptr::null_mut(), 7), 0);
                assert_eq!((*node).tag_a, WILDCARD_TAG);
                assert_eq!(LIVE, completion == 0);
            }
        }
    }
}
