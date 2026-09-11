//! `media_player_queue_refresh` — original: `FUN_0817a914` @ `0x0817a914`.
//!
//! The raw extent is **204 bytes** (`0x0817a914..0x0817a9df`): the next
//! separately linked function begins at `0x0817a9e0` with `push {r4, lr}`.
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds **10 direct `bl`
//! callers**, all unconditional, at 0x081792e8, 0x081798d4, 0x08179bd8,
//! 0x0817a8c8, 0x0817bc9c, 0x0817c724, 0x0817d118, 0x0817d404, 0x0817d630,
//! and 0x082a9c88. There are no predicated calls or direct plain-`b` tails.
//!
//! # Algorithm
//!
//! The media-player object carries an optional source handle at `+0x54`; its
//! interface is the word after that handle. The method calls that interface's
//! vtable slots `+0x138` and `+0xe4`. When both return nonzero, it notifies
//! the player through vtable slot `+0x144` with `(15, 16)`, prepares the
//! embedded queue at `+0x88` from the source interface, and uses state zero.
//! A missing or rejected source instead notifies `(15, -1)`, prepares the
//! queue from the descriptor at `+0x60`, and uses the signed state word at
//! `+0x5c`. A failed preparation returns zero immediately. Each successful
//! preparation is completed, then finalized as `(queue, 1, state)`; that
//! finalizer's return value is the method result.
//!
//! # Deliberate deviations
//!
//! The vtable-slot identities and the four queue helpers are not yet ported.
//! Target builds retain their observed dynamic/fixed transfers; host builds
//! use replaceable operations so the branch selection, argument values, call
//! order, and early return are testable. The opaque source handle and all
//! target pointers remain `u32`, preserving ARM offsets on 64-bit hosts.

use core::ptr::addr_of;

const SOURCE_READY_SLOT: usize = 0x138;
const SOURCE_USABLE_SLOT: usize = 0x0e4;
const PLAYER_NOTIFICATION_SLOT: usize = 0x144;
const QUEUE_REFRESH_EVENT: u32 = 15;
const SOURCE_READY_VALUE: i32 = 16;
const SOURCE_UNAVAILABLE_VALUE: i32 = -1;

const RETAIL_QUEUE_PREPARE_FROM_SOURCE: usize = 0x0822_040c;
const RETAIL_QUEUE_PREPARE_FALLBACK: usize = 0x0822_04c0;
const RETAIL_QUEUE_COMPLETE: usize = 0x0822_0534;
const RETAIL_QUEUE_FINALIZE: usize = 0x0822_0538;

/// Target-width prefix of the media player touched by
/// [`media_player_queue_refresh`]. `source_link` is an opaque handle whose
/// interface begins at its target address plus four bytes.
#[repr(C)]
pub struct MediaPlayerQueueOwner {
    /// +0x00: player vtable, with notification slot at +0x144.
    pub vtable: u32,
    /// +0x04..+0x53: fields not read by this method.
    pub unresolved_04: [u8; 0x50],
    /// +0x54: optional source handle.
    pub source_link: u32,
    /// +0x58: field not read by this method.
    pub unresolved_58: u32,
    /// +0x5c: fallback finalizer state.
    pub fallback_state: i32,
    /// +0x60..+0x87: fallback queue-preparation descriptor.
    pub fallback_descriptor: [u8; 0x28],
    /// +0x88: embedded queue object; its full extent is owned by unported
    /// queue helpers and need not be modelled here.
    pub queue: u8,
}

const _: () = assert!(core::mem::offset_of!(MediaPlayerQueueOwner, source_link) == 0x54);
const _: () = assert!(core::mem::offset_of!(MediaPlayerQueueOwner, fallback_state) == 0x5c);
const _: () = assert!(core::mem::offset_of!(MediaPlayerQueueOwner, fallback_descriptor) == 0x60);
const _: () = assert!(core::mem::offset_of!(MediaPlayerQueueOwner, queue) == 0x88);

/// ABI for the two source-interface probes at vtable slots +0x138 and +0xe4.
pub type SourceProbe = unsafe extern "C" fn(source_interface: u32) -> u32;
/// ABI for the player vtable notification at slot +0x144.
pub type PlayerNotification = unsafe extern "C" fn(player: u32, event: u32, value: i32) -> u32;
/// ABI for both queue preparation helpers.
pub type QueuePrepare = unsafe extern "C" fn(queue: u32, input: u32) -> u32;
/// ABI for the successful-preparation completion helper.
pub type QueueComplete = unsafe extern "C" fn(queue: u32) -> u32;
/// ABI for the queue finalizer, which supplies this method's return value.
pub type QueueFinalize = unsafe extern "C" fn(queue: u32, commit: u32, state: i32) -> u32;

/// Dynamic and fixed callees used by [`media_player_queue_refresh`].
#[derive(Clone, Copy)]
pub struct MediaPlayerQueueRefreshOps {
    pub source_ready: SourceProbe,
    pub source_usable: SourceProbe,
    pub notify: PlayerNotification,
    pub prepare_from_source: QueuePrepare,
    pub prepare_fallback: QueuePrepare,
    pub complete: QueueComplete,
    pub finalize: QueueFinalize,
}

#[cfg(target_os = "none")]
unsafe fn source_probe_at(source_interface: u32, slot: usize) -> u32 {
    let vtable = core::ptr::read_volatile(source_interface as usize as *const u32);
    let entry = core::ptr::read_volatile((vtable as usize + slot) as *const u32);
    let probe: SourceProbe = core::mem::transmute(entry as usize);
    probe(source_interface)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_source_ready(source_interface: u32) -> u32 {
    source_probe_at(source_interface, SOURCE_READY_SLOT)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_source_usable(source_interface: u32) -> u32 {
    source_probe_at(source_interface, SOURCE_USABLE_SLOT)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(player: u32, event: u32, value: i32) -> u32 {
    let vtable = core::ptr::read_volatile(player as usize as *const u32);
    let entry = core::ptr::read_volatile((vtable as usize + PLAYER_NOTIFICATION_SLOT) as *const u32);
    let notify: PlayerNotification = core::mem::transmute(entry as usize);
    notify(player, event, value)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_prepare_from_source(queue: u32, source_interface: u32) -> u32 {
    let prepare: QueuePrepare = core::mem::transmute(RETAIL_QUEUE_PREPARE_FROM_SOURCE);
    prepare(queue, source_interface)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_prepare_fallback(queue: u32, descriptor: u32) -> u32 {
    let prepare: QueuePrepare = core::mem::transmute(RETAIL_QUEUE_PREPARE_FALLBACK);
    prepare(queue, descriptor)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_complete(queue: u32) -> u32 {
    let complete: QueueComplete = core::mem::transmute(RETAIL_QUEUE_COMPLETE);
    complete(queue)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_finalize(queue: u32, commit: u32, state: i32) -> u32 {
    let finalize: QueueFinalize = core::mem::transmute(RETAIL_QUEUE_FINALIZE);
    finalize(queue, commit, state)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_source_probe(_source_interface: u32) -> u32 {
    panic!("install media-player queue refresh host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notification(_player: u32, _event: u32, _value: i32) -> u32 {
    panic!("install media-player queue refresh host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_queue: u32, _input: u32) -> u32 {
    panic!("install media-player queue refresh host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_complete(_queue: u32) -> u32 {
    panic!("install media-player queue refresh host operations")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finalize(_queue: u32, _commit: u32, _state: i32) -> u32 {
    panic!("install media-player queue refresh host operations")
}

#[cfg(target_os = "none")]
pub const DEFAULT_MEDIA_PLAYER_QUEUE_REFRESH_OPS: MediaPlayerQueueRefreshOps = MediaPlayerQueueRefreshOps {
    source_ready: retail_source_ready,
    source_usable: retail_source_usable,
    notify: retail_notify,
    prepare_from_source: retail_prepare_from_source,
    prepare_fallback: retail_prepare_fallback,
    complete: retail_complete,
    finalize: retail_finalize,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_QUEUE_REFRESH_OPS: MediaPlayerQueueRefreshOps = MediaPlayerQueueRefreshOps {
    source_ready: missing_source_probe,
    source_usable: missing_source_probe,
    notify: missing_notification,
    prepare_from_source: missing_prepare,
    prepare_fallback: missing_prepare,
    complete: missing_complete,
    finalize: missing_finalize,
};

/// Active callees. The volatile load preserves target dispatches and permits
/// host tests to replace every unported operation.
pub static mut MEDIA_PLAYER_QUEUE_REFRESH_OPS: MediaPlayerQueueRefreshOps =
    DEFAULT_MEDIA_PLAYER_QUEUE_REFRESH_OPS;

#[inline(always)]
fn ops() -> MediaPlayerQueueRefreshOps {
    unsafe { core::ptr::read_volatile(addr_of!(MEDIA_PLAYER_QUEUE_REFRESH_OPS)) }
}

/// Refreshes the player's embedded queue from its source or fallback descriptor.
///
/// Original: `FUN_0817a914` @ `0x0817a914`, 204 bytes, 10 unconditional
/// direct `bl` callers. The source must point to a readable interface when
/// `source_link` is nonzero; every queue helper and vtable call retains the
/// original's unchecked-pointer precondition.
///
/// # Safety
///
/// `player` must cover the fields through its embedded queue at `+0x88`.
/// On target, its vtable and any nonzero source handle must designate valid
/// retailOS objects with the observed vtable slots. The queue helpers may
/// access beyond the one-byte queue prefix represented here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_queue_refresh(player: *mut MediaPlayerQueueOwner) -> u32 {
    let source_link = (*player).source_link;
    let queue = addr_of!((*player).queue) as usize as u32;
    let player_word = player as usize as u32;
    let active_ops = ops();

    let state = if source_link != 0 {
        let source_interface = source_link.wrapping_add(4);
        if (active_ops.source_ready)(source_interface) != 0
            && (active_ops.source_usable)(source_interface) != 0
        {
            (active_ops.notify)(player_word, QUEUE_REFRESH_EVENT, SOURCE_READY_VALUE);
            if (active_ops.prepare_from_source)(queue, source_interface) == 0 {
                return 0;
            }
            (active_ops.complete)(queue);
            0
        } else {
            (active_ops.notify)(player_word, QUEUE_REFRESH_EVENT, SOURCE_UNAVAILABLE_VALUE);
            let descriptor = addr_of!((*player).fallback_descriptor) as usize as u32;
            if (active_ops.prepare_fallback)(queue, descriptor) == 0 {
                return 0;
            }
            (active_ops.complete)(queue);
            (*player).fallback_state
        }
    } else {
        (active_ops.notify)(player_word, QUEUE_REFRESH_EVENT, SOURCE_UNAVAILABLE_VALUE);
        let descriptor = addr_of!((*player).fallback_descriptor) as usize as u32;
        if (active_ops.prepare_fallback)(queue, descriptor) == 0 {
            return 0;
        }
        (active_ops.complete)(queue);
        (*player).fallback_state
    };

    (active_ops.finalize)(queue, 1, state)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::{Mutex, MutexGuard};

    const SOURCE_HANDLE: u32 = 0x1234_5000;
    const FINAL_RESULT: u32 = 0xfeed_beef;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut SOURCE_RESULTS: [u32; 2] = [1, 1];
    static mut SOURCE_ARGUMENT: u32 = 0;
    static mut NOTIFICATION: (u32, i32) = (0, 0);
    static mut PREPARE_RESULTS: [u32; 2] = [1, 1];
    static mut FINAL_STATE: i32 = 0;

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_source_ready(source_interface: u32) -> u32 {
        record(1);
        SOURCE_ARGUMENT = source_interface;
        SOURCE_RESULTS[0]
    }

    unsafe extern "C" fn record_source_usable(source_interface: u32) -> u32 {
        record(2);
        SOURCE_ARGUMENT = source_interface;
        SOURCE_RESULTS[1]
    }

    unsafe extern "C" fn record_notification(_player: u32, event: u32, value: i32) -> u32 {
        record(3);
        NOTIFICATION = (event, value);
        0
    }

    unsafe extern "C" fn record_prepare_source(_queue: u32, source_interface: u32) -> u32 {
        record(4);
        SOURCE_ARGUMENT = source_interface;
        PREPARE_RESULTS[0]
    }

    unsafe extern "C" fn record_prepare_fallback(_queue: u32, _descriptor: u32) -> u32 {
        record(5);
        PREPARE_RESULTS[1]
    }

    unsafe extern "C" fn record_complete(_queue: u32) -> u32 {
        record(6);
        0
    }

    unsafe extern "C" fn record_finalize(_queue: u32, commit: u32, state: i32) -> u32 {
        record(7);
        assert_eq!(commit, 1);
        FINAL_STATE = state;
        FINAL_RESULT
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(EVENTS).write([0; 8]);
            addr_of_mut!(EVENT_COUNT).write(0);
            addr_of_mut!(SOURCE_RESULTS).write([1, 1]);
            addr_of_mut!(SOURCE_ARGUMENT).write(0);
            addr_of_mut!(NOTIFICATION).write((0, 0));
            addr_of_mut!(PREPARE_RESULTS).write([1, 1]);
            addr_of_mut!(FINAL_STATE).write(0);
            addr_of_mut!(MEDIA_PLAYER_QUEUE_REFRESH_OPS).write(MediaPlayerQueueRefreshOps {
                source_ready: record_source_ready,
                source_usable: record_source_usable,
                notify: record_notification,
                prepare_from_source: record_prepare_source,
                prepare_fallback: record_prepare_fallback,
                complete: record_complete,
                finalize: record_finalize,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(MEDIA_PLAYER_QUEUE_REFRESH_OPS).write(DEFAULT_MEDIA_PLAYER_QUEUE_REFRESH_OPS);
        }
        drop(guard);
    }

    fn player(source_link: u32, fallback_state: i32) -> MediaPlayerQueueOwner {
        MediaPlayerQueueOwner {
            vtable: 0,
            unresolved_04: [0; 0x50],
            source_link,
            unresolved_58: 0,
            fallback_state,
            fallback_descriptor: [0; 0x28],
            queue: 0,
        }
    }

    fn events() -> std::vec::Vec<u8> {
        unsafe { EVENTS[..EVENT_COUNT].to_vec() }
    }

    #[test]
    fn source_path_notifies_ready_and_finalizes_zero_state() {
        let guard = install_recorder();
        let mut owner = player(SOURCE_HANDLE, -9);

        assert_eq!(unsafe { media_player_queue_refresh(addr_of_mut!(owner)) }, FINAL_RESULT);
        assert_eq!(events(), [1, 2, 3, 4, 6, 7]);
        unsafe {
            assert_eq!(SOURCE_ARGUMENT, SOURCE_HANDLE + 4);
            assert_eq!(NOTIFICATION, (QUEUE_REFRESH_EVENT, SOURCE_READY_VALUE));
            assert_eq!(FINAL_STATE, 0);
        }
        restore_default(guard);
    }

    #[test]
    fn rejected_second_source_probe_uses_fallback_state() {
        let guard = install_recorder();
        unsafe { addr_of_mut!(SOURCE_RESULTS).write([1, 0]) };
        let mut owner = player(SOURCE_HANDLE, -9);

        assert_eq!(unsafe { media_player_queue_refresh(addr_of_mut!(owner)) }, FINAL_RESULT);
        assert_eq!(events(), [1, 2, 3, 5, 6, 7]);
        unsafe {
            assert_eq!(NOTIFICATION, (QUEUE_REFRESH_EVENT, SOURCE_UNAVAILABLE_VALUE));
            assert_eq!(FINAL_STATE, -9);
        }
        restore_default(guard);
    }

    #[test]
    fn absent_source_skips_probes_and_uses_fallback() {
        let guard = install_recorder();
        let mut owner = player(0, 27);

        assert_eq!(unsafe { media_player_queue_refresh(addr_of_mut!(owner)) }, FINAL_RESULT);
        assert_eq!(events(), [3, 5, 6, 7]);
        unsafe {
            assert_eq!(NOTIFICATION, (QUEUE_REFRESH_EVENT, SOURCE_UNAVAILABLE_VALUE));
            assert_eq!(FINAL_STATE, 27);
        }
        restore_default(guard);
    }

    #[test]
    fn failed_source_prepare_returns_before_completion_or_finalization() {
        let guard = install_recorder();
        unsafe { addr_of_mut!(PREPARE_RESULTS).write([0, 1]) };
        let mut owner = player(SOURCE_HANDLE, 4);

        assert_eq!(unsafe { media_player_queue_refresh(addr_of_mut!(owner)) }, 0);
        assert_eq!(events(), [1, 2, 3, 4]);
        unsafe {
            assert_eq!(NOTIFICATION, (QUEUE_REFRESH_EVENT, SOURCE_READY_VALUE));
            assert_eq!(FINAL_STATE, 0);
        }
        restore_default(guard);
    }
}
