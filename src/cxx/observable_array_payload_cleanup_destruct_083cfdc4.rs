//! `observable_array_payload_cleanup_destruct_083cfdc4` — retailOS
//! `FUN_083cfdc4` @ **0x083cfdc4** (56 bytes: 52 bytes of code plus one
//! vtable literal).
//!
//! Raw `osos.dec` decodes thirteen A32 words from `0x083cfdc4` through the
//! tail branch at `0x083cfdf8`; `0x083cfdfc` is the vtable literal
//! `0x089a3a68`, and the next real function begins at `0x083cfe00`. Full-image
//! aligned A32 branch decoding finds two inbound plain `bl` sites and no
//! predicated inbound `bl` sites. The body makes one plain direct `bl` to
//! unported `FUN_083cfd00`, one predicated indirect `blxne` through the
//! optional payload's vtable slot `+0x1c`, and tail-branches to
//! `observable_array_destruct` @ `0x08271d2c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the optional payload at
//! `+0x14` through vtable slot `+0x1c`, run the unported payload cleanup, then
//! tail-chain into the observable-array destructor.
//!
//! Deliberate deviations: host tests replace the unknown direct cleanup and
//! target-width virtual call with seams. ARM invokes their recovered addresses;
//! Rust models the tail branch as a direct base-destructor call.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

const VTABLE_WORD: u32 = 0x089a_3a68;
const PAYLOAD_WORD: usize = 0x14 / 4;
type PayloadRelease = unsafe extern "C" fn(u32);
type PayloadCleanup = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn payload_release(payload: u32) {
    let vtable = unsafe { (payload as usize as *const u32).read_volatile() };
    let release: unsafe extern "C" fn() = unsafe {
        core::mem::transmute((vtable as usize as *const u32).add(0x1c / 4).read_volatile())
    };
    unsafe { release() };
}

#[cfg(target_os = "none")]
unsafe fn payload_cleanup(array: *mut u8) {
    let cleanup: PayloadCleanup = unsafe { core::mem::transmute(0x083c_fd00usize) };
    unsafe { cleanup(array) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_payload_release(_: u32) {
    panic!("host tests must replace OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_payload_cleanup(_: *mut u8) {
    panic!("host tests must replace OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS");
}

/// Host replacements for the payload vtable dispatch and unported
/// `FUN_083cfd00` cleanup.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS: (PayloadRelease, PayloadCleanup) =
    (missing_payload_release, missing_payload_cleanup);

/// `observable_array_payload_cleanup_destruct_083cfdc4` — `FUN_083cfdc4` @
/// 0x083cfdc4.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// payload word at `+0x14`. A nonzero payload must have a callable vtable slot
/// at `+0x1c`; the cleanup must accept the same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_payload_cleanup_destruct_083cfdc4(
    array: *mut u8,
) -> *mut u8 {
    unsafe {
        array.cast::<u32>().write_volatile(VTABLE_WORD);
        let payload = array.add(PAYLOAD_WORD * 4).cast::<u32>().read_volatile();

        #[cfg(target_os = "none")]
        {
            if payload != 0 {
                payload_release(payload);
            }
            payload_cleanup(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, cleanup) = core::ptr::read_volatile(core::ptr::addr_of!(
                OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS
            ));
            if payload != 0 {
                release(payload);
            }
            cleanup(array);
        }

        observable_array_destruct(array.cast::<ObservableArray>());
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 2] = [0; 2];
    static mut CLEANUP_RECEIVER: *mut u8 = core::ptr::null_mut();
    static mut RELEASED_PAYLOAD: u32 = 0;

    unsafe extern "C" fn record_release(payload: u32) {
        unsafe { CALLS[0] += 1; RELEASED_PAYLOAD = payload; }
    }

    unsafe extern "C" fn record_cleanup(array: *mut u8) {
        unsafe { CALLS[1] += 1; CLEANUP_RECEIVER = array; }
    }

    #[test]
    fn releases_payload_before_cleanup_and_base_teardown() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        words[PAYLOAD_WORD] = 0x1234_5000;
        unsafe {
            let old = OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS;
            OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS = (record_release, record_cleanup);
            CALLS = [0; 2]; CLEANUP_RECEIVER = core::ptr::null_mut(); RELEASED_PAYLOAD = 0;
            let result = observable_array_payload_cleanup_destruct_083cfdc4(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS = old;
            assert_eq!(result, words.as_mut_ptr().cast());
            assert_eq!(CALLS, [1, 1]);
            assert_eq!(RELEASED_PAYLOAD, 0x1234_5000);
            assert_eq!(CLEANUP_RECEIVER, words.as_mut_ptr().cast());
            assert_eq!(words[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        }
    }

    #[test]
    fn null_payload_skips_virtual_release_but_runs_cleanup() {
        let _lock = LOCK.lock();
        let mut words = [0; 6];
        unsafe {
            let old = OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS;
            OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS = (record_release, record_cleanup);
            CALLS = [0; 2];
            observable_array_payload_cleanup_destruct_083cfdc4(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_PAYLOAD_CLEANUP_DESTRUCT_083CFDC4_OPS = old;
            assert_eq!(CALLS, [0, 1]);
        }
    }
}
