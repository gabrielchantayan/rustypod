//! Display-layer reset and owned-object release.
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
}
