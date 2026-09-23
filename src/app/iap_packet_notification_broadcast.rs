//! Broadcast an iAP packet notification.
//!
//! `broadcast_iap_packet_notification` — original: `FUN_0819614c` @
//! **0x0819614c**. The true extent is **100 bytes**: 92 bytes of code through
//! `pop {r4,pc}` at 0x081961a8, followed by its literal-pool word
//! 0x089ccc04; the next function begins at 0x081961b0. The code has **3 plain
//! unconditional `bl` calls** and **0 predicated `bl` calls**.
//!
//! Algorithm: build an otherwise-uninitialized 0x410-byte event payload with
//! bytes 0, 8, 9, and 10 set to 0x80, 0x0f, 0x85, and packet+0x22,
//! respectively; lock the context mutex at context+0x2e0; broadcast event
//! kind 12; then unlock it.
//!
//! # Deliberate deviations
//!
//! The firmware literal-backed context pointer is represented by a host seam
//! outside target builds. The payload intentionally remains uninitialized
//! except for the four stores performed by retailOS.

use core::mem::MaybeUninit;
#[cfg(not(target_os = "none"))]
use core::ptr;

#[cfg(target_os = "none")]
use crate::app::event_hub::event_hub_broadcast;
use crate::kernel::posix_mutex::PosixMutex;
#[cfg(target_os = "none")]
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock};

const PACKET_NOTIFICATION_BYTE_OFFSET: usize = 0x22;
const CONTEXT_MUTEX_OFFSET: usize = 0x2e0;
const EVENT_KIND: u32 = 12;
const EVENT_PAYLOAD_LEN: usize = 0x410;
const EVENT_PAYLOAD_HEADER: u8 = 0x80;
const EVENT_PAYLOAD_TYPE: u8 = 0x0f;
const EVENT_PAYLOAD_CODE: u8 = 0x85;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn notification_context() -> *mut u8 {
    (0x089c_cc04usize as *const *mut u8).read_volatile()
}

#[cfg(not(target_os = "none"))]
struct PacketNotificationOps {
    context: unsafe fn() -> *mut u8,
    lock: unsafe fn(*mut PosixMutex) -> u32,
    broadcast: unsafe fn(u32, u32, usize, u32),
    unlock: unsafe fn(*mut PosixMutex) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe fn null_context() -> *mut u8 {
    ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe fn noop_lock(_: *mut PosixMutex) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe fn noop_broadcast(_: u32, _: u32, _: usize, _: u32) {}

#[cfg(not(target_os = "none"))]
static mut PACKET_NOTIFICATION_OPS: PacketNotificationOps = PacketNotificationOps {
    context: null_context,
    lock: noop_lock,
    broadcast: noop_broadcast,
    unlock: noop_lock,
};

/// `broadcast_iap_packet_notification` — original: `FUN_0819614c` @
/// 0x0819614c (100 bytes including its literal; 3 plain `bl` calls, no
/// predicated `bl` calls).
///
/// # Safety
///
/// `packet` must be readable at +0x22. The literal-backed notification context
/// and its mutex must be initialized, as required by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn broadcast_iap_packet_notification(
    _unused_context: *mut u8,
    packet: *const u8,
) {
    let mut payload = MaybeUninit::<[u8; EVENT_PAYLOAD_LEN]>::uninit();
    let payload = payload.as_mut_ptr().cast::<u8>();
    payload.write(EVENT_PAYLOAD_HEADER);
    payload.add(8).write(EVENT_PAYLOAD_TYPE);
    payload.add(9).write(EVENT_PAYLOAD_CODE);
    payload.add(10).write(packet.add(PACKET_NOTIFICATION_BYTE_OFFSET).read());

    #[cfg(target_os = "none")]
    {
        let mutex = notification_context().add(CONTEXT_MUTEX_OFFSET).cast::<PosixMutex>();
        posix_mutex_lock(mutex);
        event_hub_broadcast(EVENT_KIND, 0, payload as usize, EVENT_PAYLOAD_LEN as u32);
        posix_mutex_unlock(mutex);
    }

    #[cfg(not(target_os = "none"))]
    {
        let ops = ptr::read_volatile(ptr::addr_of!(PACKET_NOTIFICATION_OPS));
        let mutex = (ops.context)().add(CONTEXT_MUTEX_OFFSET).cast::<PosixMutex>();
        (ops.lock)(mutex);
        (ops.broadcast)(EVENT_KIND, 0, payload as usize, EVENT_PAYLOAD_LEN as u32);
        (ops.unlock)(mutex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: [u8; CONTEXT_MUTEX_OFFSET + 4] = [0; CONTEXT_MUTEX_OFFSET + 4];
    static mut CALLS: [u32; 4] = [0; 4];
    static mut PAYLOAD_BYTES: [u8; 4] = [0; 4];
    static mut MUTEX: *mut PosixMutex = ptr::null_mut();

    unsafe fn test_context() -> *mut u8 { ptr::addr_of_mut!(CONTEXT).cast() }
    unsafe fn record_lock(mutex: *mut PosixMutex) -> u32 {
        MUTEX = mutex;
        CALLS[0] += 1;
        0
    }
    unsafe fn record_broadcast(kind: u32, arg: u32, payload: usize, len: u32) {
        CALLS[1] = kind;
        CALLS[2] = arg;
        CALLS[3] = len;
        let payload = payload as *const u8;
        PAYLOAD_BYTES = [payload.read(), payload.add(8).read(), payload.add(9).read(), payload.add(10).read()];
    }
    unsafe fn record_unlock(mutex: *mut PosixMutex) -> u32 {
        assert_eq!(mutex, MUTEX);
        CALLS[0] += 1;
        0
    }

    #[test]
    fn builds_packet_notification_and_holds_context_mutex() {
        let _guard = TEST_LOCK.lock();
        let saved = unsafe { ptr::read(ptr::addr_of!(PACKET_NOTIFICATION_OPS)) };
        unsafe {
            PACKET_NOTIFICATION_OPS = PacketNotificationOps {
                context: test_context,
                lock: record_lock,
                broadcast: record_broadcast,
                unlock: record_unlock,
            };
            CALLS = [0; 4];
            PAYLOAD_BYTES = [0; 4];
            MUTEX = ptr::null_mut();

            let mut packet = [0u8; PACKET_NOTIFICATION_BYTE_OFFSET + 1];
            packet[PACKET_NOTIFICATION_BYTE_OFFSET] = 0xa7;
            broadcast_iap_packet_notification(ptr::null_mut(), packet.as_ptr());

            assert_eq!(CALLS, [2, EVENT_KIND, 0, EVENT_PAYLOAD_LEN as u32]);
            assert_eq!(MUTEX, test_context().add(CONTEXT_MUTEX_OFFSET).cast());
            assert_eq!(PAYLOAD_BYTES, [EVENT_PAYLOAD_HEADER, EVENT_PAYLOAD_TYPE, EVENT_PAYLOAD_CODE, 0xa7]);
            PACKET_NOTIFICATION_OPS = saved;
        }
    }
}
