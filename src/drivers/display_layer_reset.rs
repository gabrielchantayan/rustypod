//! Display-layer reset and pending-object cleanup.
//!
//! [`layer_reset`] — original: `FUN_08120094` @ **0x08120094**.
//! Raw `osos.dec` establishes its true **160-byte** extent
//! `0x08120094..0x08120134`; the next separately linked function starts with
//! a tail branch at `0x08120134`. Decoding every ARM direct-branch word finds
//! **5 plain `bl` callers** (0x081205fc, 0x08142848, 0x0816e4d4, 0x08292294,
//! and 0x082962bc), and the body has **3 plain `bl` plus 5 predicated `blx`
//! calls**.
//!
//! # Algorithm
//!
//! Locks the embedded mutex at `+0x78`, runs the unported embedded-state reset
//! at `0x0812084c`, releases each non-null object at `+0x4c..+0x5c` through
//! vtable slot `+0x04`, clears only the first three object words, clears the
//! active byte at `+0x40`, then unlocks. The fourth and fifth object words are
//! deliberately retained after their release, exactly as the ARM stores show.
//!
//! # Deliberate deviations
//!
//! The unported `0x0812084c` is an address seam. Host builds likewise replace
//! target-width vtable dispatch with a recorder seam: host pointers are wider
//! than the firmware's four-byte object words. ARM builds perform the verified
//! two-load slot-`+0x04` dispatch directly.
//!
//! [`layer_pending_object_cleanup`] — original: `FUN_08120700` @
//! **0x08120700** (**68 bytes**, `0x08120700..0x08120743`; the next separately
//! linked function starts at `0x08120744`). Raw A32 decoding finds **2 plain**
//! inbound `bl` calls (0x081d8b4c, 0x081d8b6c), **1 predicated** `blne` caller
//! (0x081d8f38), one outbound plain `bl`, no predicated outbound `bl`, one
//! `blx` vtable dispatch, and one tail branch.
//!
//! # Algorithm
//!
//! Clears the layer byte at `+0x1bd`. With a non-null pending object at
//! `+0x60`, calls the unported `0x0810667c` with `(object, 1)`, invokes its
//! vtable slot `+0x04`, and clears the word. Otherwise it tail-calls
//! `condvar_signal` on the embedded condition variable at `+0x80`.
//!
//! # Deliberate deviations
//!
//! The unidentified `0x0810667c` call and host vtable dispatch are explicit
//! seams. ARM retains their verified address and slot dispatch; host tests use
//! target-width words rather than host pointer offsets.

use crate::kernel::condvar::{condvar_signal, CondVar};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

#[cfg(test)]
extern crate std;

type EmbeddedStateReset = unsafe extern "C" fn(*mut u32);
type ObjectRelease = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_embedded_state_reset(display: *mut u32) {
    let reset: EmbeddedStateReset = core::mem::transmute(0x0812_084cusize);
    reset(display);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_embedded_state_reset(_display: *mut u32) {}

#[cfg(target_os = "none")]
static mut EMBEDDED_STATE_RESET: EmbeddedStateReset = firmware_embedded_state_reset;
#[cfg(not(target_os = "none"))]
static mut EMBEDDED_STATE_RESET: EmbeddedStateReset = missing_embedded_state_reset;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_release(_object: u32) {}

#[cfg(not(target_os = "none"))]
static mut OBJECT_RELEASE: ObjectRelease = missing_object_release;

#[inline(always)]
unsafe fn reset_embedded_state(display: *mut u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(EMBEDDED_STATE_RESET))(display);
}

#[inline(always)]
unsafe fn release_object(object: u32) {
    #[cfg(target_os = "none")]
    {
        let object = object as usize as *mut *const u32;
        let vtable = object.read();
        let release: unsafe extern "C" fn(*mut *const u32) = core::mem::transmute(vtable.add(1).read());
        release(object);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_RELEASE))(object);
    }
}

/// layer_reset — original: `FUN_08120094` @ `0x08120094` (160 bytes).
///
/// Locks the layer at `+0x78`, resets its embedded state, releases five
/// nullable owned objects through vtable slot `+0x04`, clears the first three
/// ownership words and active flag, then unlocks. The object words are always
/// target-width u32 indices, preserving their ARM offsets on a 64-bit host.
/// The final two words remain nonzero after their release, as in retailOS.
///
/// # Safety
///
/// `display` must point to a live firmware display object with a mutex at

/// `+0x78`; each nonzero object word must name a valid slot-`+0x04` object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_reset(display: *mut u32) -> i32 {
    let mutex = display.add(0x78 / 4).cast::<Mutex>();
    mutex_lock(mutex);
    reset_embedded_state(display);

    for word in [0x4c / 4, 0x50 / 4, 0x54 / 4, 0x58 / 4, 0x5c / 4] {
        let object = display.add(word).read();
        if object != 0 {
            release_object(object);
        }
    }
    display.add(0x4c / 4).write(0);
    display.add(0x50 / 4).write(0);
    display.add(0x54 / 4).write(0);
    display.cast::<u8>().add(0x40).write(0);
    mutex_unlock(mutex);
    0
}
type PendingObjectStop = unsafe extern "C" fn(*mut u32, u32);
type PendingObjectRelease = unsafe extern "C" fn(u32);
type PendingCleanupSignal = unsafe extern "C" fn(*mut CondVar);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pending_object_stop(object: *mut u32, flag: u32) {
    let stop: PendingObjectStop = core::mem::transmute(0x0810_667cusize);
    stop(object, flag);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pending_object_stop(_object: *mut u32, _flag: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pending_cleanup_signal(condvar: *mut CondVar) {
    condvar_signal(condvar);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pending_cleanup_signal(_condvar: *mut CondVar) {}

#[cfg(target_os = "none")]
static mut PENDING_OBJECT_STOP: PendingObjectStop = firmware_pending_object_stop;
#[cfg(not(target_os = "none"))]
static mut PENDING_OBJECT_STOP: PendingObjectStop = missing_pending_object_stop;
#[cfg(not(target_os = "none"))]
static mut PENDING_OBJECT_RELEASE: PendingObjectRelease = missing_object_release;
#[cfg(target_os = "none")]
static mut PENDING_CLEANUP_SIGNAL: PendingCleanupSignal = firmware_pending_cleanup_signal;
#[cfg(not(target_os = "none"))]
static mut PENDING_CLEANUP_SIGNAL: PendingCleanupSignal = missing_pending_cleanup_signal;

#[inline(always)]
unsafe fn release_pending_object(object: u32) {
    #[cfg(target_os = "none")]
    {
        let object = object as usize as *mut *const u32;
        let vtable = object.read();
        let release: unsafe extern "C" fn(*mut *const u32) = core::mem::transmute(vtable.add(1).read());
        release(object);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(PENDING_OBJECT_RELEASE))(object);
    }
}

/// layer_pending_object_cleanup — original: `FUN_08120700` @ `0x08120700`
/// (68 bytes; 2 plain and 1 predicated inbound `bl` call sites).
///
/// Clears the layer's pending byte, then either stops, releases, and clears its
/// pending target-width object at `+0x60`, or signals its `+0x80` condition
/// variable when no object is pending.
///
/// # Safety
///
/// `layer` must point to a live firmware layer object. Its `+0x60` word, if
/// nonzero, must name a valid slot-`+0x04` object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn layer_pending_object_cleanup(layer: *mut u32) {
    layer.cast::<u8>().add(0x1bd).write(0);
    let object = layer.add(0x60 / 4).read();
    if object == 0 {
        core::ptr::read_volatile(core::ptr::addr_of!(PENDING_CLEANUP_SIGNAL))(
            layer.cast::<u8>().add(0x80).cast::<CondVar>(),
        );
        return;
    }

    core::ptr::read_volatile(core::ptr::addr_of!(PENDING_OBJECT_STOP))(
        object as usize as *mut u32,
        1,
    );
    release_pending_object(object);
    layer.add(0x60 / 4).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as TestMutex;

    static TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static mut EVENTS: [u32; 6] = [0; 6];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn record_reset(_display: *mut u32) {
        EVENTS[EVENT_COUNT] = 0xffff_ffff;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_release(object: u32) {
        EVENTS[EVENT_COUNT] = object;
        EVENT_COUNT += 1;
    }

    unsafe fn install_seams() {
        EMBEDDED_STATE_RESET = record_reset;
        OBJECT_RELEASE = record_release;
        EVENTS = [0; 6];
        EVENT_COUNT = 0;
    }

    #[test]
    fn releases_every_nonnull_word_and_only_clears_the_first_three() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u64; 32];
        let display = storage.as_mut_ptr().cast::<u32>();
        unsafe {
            display.add(0x4c / 4).write(11);
            display.add(0x50 / 4).write(22);
            display.add(0x54 / 4).write(33);
            display.add(0x58 / 4).write(44);
            display.add(0x5c / 4).write(55);
            display.cast::<u8>().add(0x40).write(1);
            install_seams();
            assert_eq!(layer_reset(display), 0);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0xffff_ffff, 11, 22, 33, 44, 55]);
            assert_eq!(display.add(0x4c / 4).read(), 0);
            assert_eq!(display.add(0x50 / 4).read(), 0);
            assert_eq!(display.add(0x54 / 4).read(), 0);
            assert_eq!(display.add(0x58 / 4).read(), 44);
            assert_eq!(display.add(0x5c / 4).read(), 55);
            assert_eq!(display.cast::<u8>().add(0x40).read(), 0);
        }
    }

    #[test]
    fn null_words_skip_only_their_virtual_releases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u64; 32];
        unsafe {
            install_seams();
            layer_reset(storage.as_mut_ptr().cast::<u32>());
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0xffff_ffff]);
        }
    }

    unsafe extern "C" fn record_pending_stop(object: *mut u32, flag: u32) {
        EVENTS[EVENT_COUNT] = object as usize as u32;
        EVENT_COUNT += 1;
        EVENTS[EVENT_COUNT] = flag;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_pending_release(object: u32) {
        EVENTS[EVENT_COUNT] = object;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_pending_signal(_condvar: *mut CondVar) {
        EVENTS[EVENT_COUNT] = 0xffff_fffe;
        EVENT_COUNT += 1;
    }

    unsafe fn install_pending_cleanup_seams() {
        PENDING_OBJECT_STOP = record_pending_stop;
        PENDING_OBJECT_RELEASE = record_pending_release;
        PENDING_CLEANUP_SIGNAL = record_pending_signal;
        EVENTS = [0; 6];
        EVENT_COUNT = 0;
    }

    #[test]
    fn pending_object_is_stopped_released_and_cleared_in_order() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u64; 64];
        let layer = storage.as_mut_ptr().cast::<u32>();
        unsafe {
            layer.add(0x60 / 4).write(0x1234_5678);
            layer.cast::<u8>().add(0x1bd).write(1);
            install_pending_cleanup_seams();
            layer_pending_object_cleanup(layer);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0x1234_5678, 1, 0x1234_5678]);
            assert_eq!(layer.add(0x60 / 4).read(), 0);
            assert_eq!(layer.cast::<u8>().add(0x1bd).read(), 0);
        }
    }

    #[test]
    fn no_pending_object_signals_condvar_without_release() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut storage = [0u64; 64];
        let layer = storage.as_mut_ptr().cast::<u32>();
        unsafe {
            layer.cast::<u8>().add(0x1bd).write(1);
            install_pending_cleanup_seams();
            layer_pending_object_cleanup(layer);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[0xffff_fffe]);
            assert_eq!(layer.add(0x60 / 4).read(), 0);
            assert_eq!(layer.cast::<u8>().add(0x1bd).read(), 0);
        }
    }
}
