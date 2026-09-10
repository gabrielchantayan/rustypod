//! Dispatch an iAP packet event through its packet vtable.
//!
//! `dispatch_iap_packet_event` — original: `FUN_081a9728` @ **0x081a9728**.
//! Raw bytes give a **176-byte** extent: 172 bytes of code through `bx r1` @
//! 0x081a97d4, followed by the separately linked next function at 0x081a97d8.
//! A complete decode of every ARM `B`/`BL` word in `osos.dec` finds **11 direct
//! `bl` call sites**: 10 `blne` calls gated by the event-dispatch enable byte
//! at 0x089ccb6c and one unconditional `bl`; no plain `b` targets it.
//!
//! Algorithm: move the packet from `r1` to `r0`, then select one of ten packet
//! vtable slots by event code. Events 0 through 9 select slots +0xe0, +0xd8,
//! +0xe4, +0xdc, +0xec, +0xf0, +0xfc, +0xf8, +0xf4, and +0xe8 respectively,
//! and tail-dispatch it with the packet as the first argument. Out-of-range
//! event codes return the packet unchanged without dereferencing it.
//!
//! # Deliberate deviations
//!
//! The ten callback identities and return types are not recovered: each is an
//! indirect vtable target and the direct callers discard `r0`. Target builds
//! retain the verified raw slot dispatch and expose its `r0` result as a packet
//! pointer. Host builds use a slot-index dispatch seam because host function
//! pointers cannot fit the target's 32-bit vtable words.

#[cfg(not(target_os = "none"))]
use core::ptr;

const EVENT_VTABLE_OFFSETS: [u32; 10] = [
    0xe0, 0xd8, 0xe4, 0xdc, 0xec, 0xf0, 0xfc, 0xf8, 0xf4, 0xe8,
];

type PacketEventCallback = unsafe extern "C" fn(packet: *mut u8) -> *mut u8;

/// Host dispatch for the unrecovered packet-event vtable callbacks.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct IapPacketEventDispatchOps {
    pub dispatch: unsafe extern "C" fn(packet: *mut u8, vtable_offset: u32) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_packet_event_callback(packet: *mut u8, _vtable_offset: u32) -> *mut u8 {
    packet
}

/// Host default keeps the stock out-of-range result and makes recovered event
/// dispatch explicit in tests until the packet class's concrete callbacks are
/// ported.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_IAP_PACKET_EVENT_DISPATCH_OPS: IapPacketEventDispatchOps =
    IapPacketEventDispatchOps { dispatch: missing_packet_event_callback };

/// Active host implementation of the packet-event vtable dispatch.
#[cfg(not(target_os = "none"))]
pub static mut IAP_PACKET_EVENT_DISPATCH_OPS: IapPacketEventDispatchOps =
    DEFAULT_IAP_PACKET_EVENT_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_packet_event_on_host(packet: *mut u8, vtable_offset: u32) -> *mut u8 {
    (ptr::read_volatile(ptr::addr_of!(IAP_PACKET_EVENT_DISPATCH_OPS.dispatch)))(packet, vtable_offset)
}

/// dispatch_iap_packet_event — original: `FUN_081a9728` @ 0x081a9728 (176
/// bytes; 11 direct `bl` call sites: 10 `blne`, one unconditional).
///
/// Selects and tail-dispatches the iAP packet callback for `event`. Event
/// values outside 0..=9 preserve the packet in `r0`, exactly like the raw
/// default `bx lr` path.
///
/// # Safety
///
/// For a recognized event on firmware, `packet` must point to an object whose
/// first target-width word is a valid vtable containing the selected callback.
/// The callback's unrecovered contract remains unchecked, as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.dispatch_iap_packet_event")]
pub unsafe extern "C" fn dispatch_iap_packet_event(
    _context: *mut u8,
    packet: *mut u8,
    event: u32,
) -> *mut u8 {
    let Some(&vtable_offset) = EVENT_VTABLE_OFFSETS.get(event as usize) else {
        return packet;
    };

    #[cfg(target_os = "none")]
    {
        let vtable = packet.cast::<u32>().read() as usize as *const u32;
        let callback_address = vtable.add((vtable_offset / 4) as usize).read() as usize;
        let callback: PacketEventCallback = core::mem::transmute(callback_address);
        callback(packet)
    }

    #[cfg(not(target_os = "none"))]
    {
        dispatch_packet_event_on_host(packet, vtable_offset)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        dispatch_iap_packet_event, IapPacketEventDispatchOps,
        DEFAULT_IAP_PACKET_EVENT_DISPATCH_OPS, IAP_PACKET_EVENT_DISPATCH_OPS,
    };
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: u32 = 0;
    static mut LAST_PACKET: *mut u8 = ptr::null_mut();
    static mut LAST_VTABLE_OFFSET: u32 = 0;

    unsafe extern "C" fn recording_dispatch(packet: *mut u8, vtable_offset: u32) -> *mut u8 {
        CALL_COUNT += 1;
        LAST_PACKET = packet;
        LAST_VTABLE_OFFSET = vtable_offset;
        packet.wrapping_add(1)
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: IapPacketEventDispatchOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { IAP_PACKET_EVENT_DISPATCH_OPS = self.previous_ops };
        }
    }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous_ops = unsafe { IAP_PACKET_EVENT_DISPATCH_OPS };
        unsafe {
            CALL_COUNT = 0;
            LAST_PACKET = ptr::null_mut();
            LAST_VTABLE_OFFSET = 0;
            IAP_PACKET_EVENT_DISPATCH_OPS = IapPacketEventDispatchOps {
                dispatch: recording_dispatch,
            };
        }
        Bench { _lock: lock, previous_ops }
    }

    #[test]
    fn each_event_selects_its_nonmonotonic_vtable_slot() {
        let _bench = bench();
        let packet = 0x1234_5000usize as *mut u8;
        let expected_offsets = [0xe0, 0xd8, 0xe4, 0xdc, 0xec, 0xf0, 0xfc, 0xf8, 0xf4, 0xe8];

        for (event, expected_offset) in expected_offsets.into_iter().enumerate() {
            unsafe {
                CALL_COUNT = 0;
                let result = dispatch_iap_packet_event(ptr::null_mut(), packet, event as u32);
                assert_eq!(result, packet.wrapping_add(1));
                assert_eq!(CALL_COUNT, 1);
                assert_eq!(LAST_PACKET, packet);
                assert_eq!(LAST_VTABLE_OFFSET, expected_offset);
            }
        }
    }

    #[test]
    fn out_of_range_events_return_packet_without_dispatch() {
        let _bench = bench();
        let packet = 0xfeed_0000usize as *mut u8;

        for event in [10, u32::MAX] {
            unsafe {
                assert_eq!(dispatch_iap_packet_event(ptr::null_mut(), packet, event), packet);
                assert_eq!(CALL_COUNT, 0);
                assert_eq!(LAST_PACKET, ptr::null_mut());
            }
        }
    }

    #[test]
    fn host_default_preserves_packet_for_recognized_event() {
        let _bench = bench();
        let packet = 0x4000usize as *mut u8;
        unsafe { IAP_PACKET_EVENT_DISPATCH_OPS = DEFAULT_IAP_PACKET_EVENT_DISPATCH_OPS };

        assert_eq!(
            unsafe { dispatch_iap_packet_event(ptr::null_mut(), packet, 0) },
            packet,
        );
    }
}
