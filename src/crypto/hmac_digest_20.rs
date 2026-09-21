//! HMAC wrapper for the proprietary 20-byte digest.
//!
//! `hmac_digest_20` — original: `FUN_08324364` @ `0x08324364` (**84 bytes**,
//! `0x08324364..0x083243b8`; the next real function starts at `0x083243b8`).
//! Raw ARM decoding verifies three plain `bl` call sites and no predicated
//! `bl` calls.
//!
//! # Algorithm
//!
//! Allocate the 0xa8-byte proprietary digest context, initialize its HMAC key
//! schedule with algorithm selector 2, feed the supplied input, then finalize
//! the 20-byte digest into `output`.
//!
//! # Deliberate deviations
//!
//! The retail body reserves 0xa8 bytes directly on the stack. This port uses
//! an explicitly four-byte-aligned byte array of the same size. The unported
//! HMAC-key-schedule and digest-final workers remain volatile firmware seams;
//! `input_dispatch` is already ported and preserves its retail tail seam.

use super::digest_init::DigestCtx;
use core::mem::MaybeUninit;
#[cfg(not(target_arch = "arm"))]
use crate::util::input_dispatch;

const HMAC_KEY_SCHEDULE_ADDRESS: usize = 0x0835_ab54;
const DIGEST_FINAL_ADDRESS: usize = 0x0834_f42c;
const DIGEST_CONTEXT_SIZE: usize = 0xa8;
const DIGEST_KIND_20: u32 = 2;

#[repr(align(4))]
struct DigestContextStorage([u8; DIGEST_CONTEXT_SIZE]);

/// ABI of the HMAC key-schedule worker @ `0x0835ab54`.
pub type HmacKeyScheduleFn = unsafe extern "C" fn(u32, *mut DigestCtx, *const u8, u32);
/// ABI of the proprietary digest-final worker @ `0x0834f42c`.
pub type DigestFinalFn = unsafe extern "C" fn(*mut u8, *mut DigestCtx);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_hmac_key_schedule(
    key_len: u32,
    ctx: *mut DigestCtx,
    key: *const u8,
    algorithm: u32,
) {
    let schedule: HmacKeyScheduleFn = unsafe { core::mem::transmute(HMAC_KEY_SCHEDULE_ADDRESS) };
    unsafe { schedule(key_len, ctx, key, algorithm) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_hmac_key_schedule(
    _key_len: u32,
    _ctx: *mut DigestCtx,
    _key: *const u8,
    _algorithm: u32,
) {
    panic!("hmac_digest_20 requires HMAC key schedule worker 0x0835ab54")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_digest_final(output: *mut u8, ctx: *mut DigestCtx) {
    let finalizer: DigestFinalFn = unsafe { core::mem::transmute(DIGEST_FINAL_ADDRESS) };
    unsafe { finalizer(output, ctx) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_digest_final(_output: *mut u8, _ctx: *mut DigestCtx) {
    panic!("hmac_digest_20 requires digest-final worker 0x0834f42c")
}

/// Active HMAC key-schedule worker. Host tests replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut HMAC_KEY_SCHEDULE: HmacKeyScheduleFn = firmware_hmac_key_schedule;
#[cfg(not(target_os = "none"))]
pub static mut HMAC_KEY_SCHEDULE: HmacKeyScheduleFn = missing_hmac_key_schedule;
/// Active digest-final worker. Host tests replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut DIGEST_FINAL: DigestFinalFn = firmware_digest_final;
#[cfg(not(target_os = "none"))]
pub static mut DIGEST_FINAL: DigestFinalFn = missing_digest_final;

#[inline(always)]
unsafe fn hmac_key_schedule() -> HmacKeyScheduleFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HMAC_KEY_SCHEDULE)) }
}

#[inline(always)]
unsafe fn digest_final() -> DigestFinalFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIGEST_FINAL)) }
}
#[cfg(target_arch = "arm")]
unsafe fn digest_input_dispatch(input: *mut u8, input_len: u32, ctx: *mut u8) {
    unsafe extern "C" {
        #[link_name = "input_dispatch"]
        fn retail_input_dispatch(input: *mut u8, input_len: u32, ctx: *mut u8) -> u32;
    }
    unsafe { retail_input_dispatch(input, input_len, ctx) };
}

#[cfg(not(target_arch = "arm"))]
unsafe fn digest_input_dispatch(input: *mut u8, input_len: u32, ctx: *mut u8) {
    unsafe { input_dispatch::input_dispatch(input, input_len, ctx) };
}


/// Compute the proprietary algorithm-2 HMAC for `input` using `key`.
///
/// # Safety
/// `key` and `input` must be accepted by their retail workers for the supplied
/// lengths; `output` must point to space accepted by digest-final. As retail
/// does, this wrapper performs no validation and discards worker return values.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hmac_digest_20(
    output: *mut u8,
    input_len: u32,
    input: *mut u8,
    key: *const u8,
    key_len: u32,
) {
    let mut storage = MaybeUninit::<DigestContextStorage>::uninit();
    let ctx = storage.as_mut_ptr().cast::<u8>().cast::<DigestCtx>();
    unsafe {
        hmac_key_schedule()(key_len, ctx, key, DIGEST_KIND_20);
        digest_input_dispatch(input, input_len, ctx.cast());
        digest_final()(output, ctx);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::input_dispatch::{Retail08317f9c, RETAIL_08317F9C};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;
    static mut SCHEDULE_ARGS: (u32, usize, usize, u32) = (0, 0, 0, 0);
    static mut INPUT_ARGS: (u32, usize, usize) = (0, 0, 0);
    static mut FINAL_ARGS: (usize, usize) = (0, 0);

    unsafe fn event(value: u8) {
        unsafe { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1 };
    }

    unsafe extern "C" fn record_schedule(key_len: u32, ctx: *mut DigestCtx, key: *const u8, algorithm: u32) {
        unsafe { SCHEDULE_ARGS = (key_len, ctx as usize, key as usize, algorithm); event(1) };
    }

    unsafe extern "C" fn record_input(length: u32, input: *mut u8, ctx: *mut u8) -> u32 {
        unsafe { INPUT_ARGS = (length, input as usize, ctx as usize); event(2) };
        0
    }

    unsafe extern "C" fn record_final(output: *mut u8, ctx: *mut DigestCtx) {
        unsafe { FINAL_ARGS = (output as usize, ctx as usize); event(3) };
    }

    struct Restore(HmacKeyScheduleFn, DigestFinalFn, Retail08317f9c);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                HMAC_KEY_SCHEDULE = self.0;
                DIGEST_FINAL = self.1;
                RETAIL_08317F9C = self.2;
            }
        }
    }

    #[test]
    fn schedules_updates_and_finalizes_with_verbatim_arguments() {
        let _lock = TEST_LOCK.lock();
        let restore = unsafe {
            let restore = Restore(HMAC_KEY_SCHEDULE, DIGEST_FINAL, RETAIL_08317F9C);
            HMAC_KEY_SCHEDULE = record_schedule;
            DIGEST_FINAL = record_final;
            RETAIL_08317F9C = record_input;
            EVENTS = [0; 3];
            EVENT_COUNT = 0;
            SCHEDULE_ARGS = (0, 0, 0, 0);
            INPUT_ARGS = (0, 0, 0);
            FINAL_ARGS = (0, 0);
            restore
        };
        let mut output = [0u8; 20];
        let mut input = [0x12u8, 0x34];
        let key = [0xffu8; 32];

        unsafe { hmac_digest_20(output.as_mut_ptr(), u32::MAX, input.as_mut_ptr(), key.as_ptr(), 0) };

        unsafe {
            assert_eq!(EVENTS, [1, 2, 3]);
            assert_eq!(SCHEDULE_ARGS.0, 0);
            assert_eq!(SCHEDULE_ARGS.2, key.as_ptr() as usize);
            assert_eq!(SCHEDULE_ARGS.3, DIGEST_KIND_20);
            assert_eq!(INPUT_ARGS.0, u32::MAX);
            assert_eq!(INPUT_ARGS.1, input.as_mut_ptr() as usize);
            assert_eq!(INPUT_ARGS.2, SCHEDULE_ARGS.1);
            assert_eq!(FINAL_ARGS, (output.as_mut_ptr() as usize, SCHEDULE_ARGS.1));
        }
        drop(restore);
    }
}
