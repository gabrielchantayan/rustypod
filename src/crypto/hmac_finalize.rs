//! Finalize Apple's proprietary HMAC construction.
//!
//! `hmac_finalize` — original: `FUN_083385b8` @ `0x083385b8` (92 bytes,
//! `0x083385b8..0x08338614`; the next separately linked function starts at
//! `0x08338614`). Raw ARM contains five unconditional direct `bl` calls and
//! no predicated `bl` calls. Whole-image branch decoding finds two inbound
//! plain unconditional `bl` sites and no predicated inbound calls.
//!
//! # Algorithm
//!
//! Finalize the current inner digest into a 20-byte local, reinitialize the
//! embedded digest with its stored algorithm, hash the saved 64-byte outer
//! pad and the inner digest, then finalize through the output transform.
//!
//! # Deliberate deviations
//!
//! The retail stack local starts at `sp + 4`; Rust uses a four-byte-aligned
//! 20-byte array. The unported core-final and output-transform workers stay
//! volatile fixed-address seams; `digest_init` and the established
//! `DIGEST_UPDATE` seam preserve the remaining call boundaries.

use super::digest_init::{digest_init, DigestCtx};
use super::digest_update_u32::DIGEST_UPDATE;

const CORE_DIGEST_FINAL_ADDRESS: usize = 0x082f_bbfc;
const OUTPUT_DIGEST_FINAL_ADDRESS: usize = 0x0831_8200;
const OUTER_PAD_LEN: u32 = 64;

/// Digest context plus the HMAC outer pad stored immediately after it.
#[repr(C)]
pub struct HmacCtx {
    pub digest: DigestCtx,
    pub outer_pad: [u8; OUTER_PAD_LEN as usize],
}

/// ABI of the core digest finalizer @ `0x082fbbfc`.
pub type CoreDigestFinalFn = unsafe extern "C" fn(*mut u8, *mut DigestCtx);
/// ABI of the digest finalizer/output transform @ `0x08318200`.
pub type OutputDigestFinalFn = unsafe extern "C" fn(*mut DigestCtx, *mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_core_digest_final(output: *mut u8, ctx: *mut DigestCtx) {
    unsafe {
        core::mem::transmute::<usize, CoreDigestFinalFn>(CORE_DIGEST_FINAL_ADDRESS)(output, ctx)
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_core_digest_final(_output: *mut u8, _ctx: *mut DigestCtx) {
    panic!("hmac_finalize requires core digest final worker 0x082fbbfc")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_output_digest_final(ctx: *mut DigestCtx, output: *mut u8) -> u32 {
    unsafe {
        core::mem::transmute::<usize, OutputDigestFinalFn>(OUTPUT_DIGEST_FINAL_ADDRESS)(ctx, output)
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_output_digest_final(_ctx: *mut DigestCtx, _output: *mut u8) -> u32 {
    panic!("hmac_finalize requires output digest final worker 0x08318200")
}

/// Active core finalizer. Host tests replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut CORE_DIGEST_FINAL: CoreDigestFinalFn = firmware_core_digest_final;
#[cfg(not(target_os = "none"))]
pub static mut CORE_DIGEST_FINAL: CoreDigestFinalFn = missing_core_digest_final;
/// Active output transform. Host tests replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut OUTPUT_DIGEST_FINAL: OutputDigestFinalFn = firmware_output_digest_final;
#[cfg(not(target_os = "none"))]
pub static mut OUTPUT_DIGEST_FINAL: OutputDigestFinalFn = missing_output_digest_final;

#[inline(always)]
unsafe fn core_digest_final() -> CoreDigestFinalFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CORE_DIGEST_FINAL)) }
}

#[inline(always)]
unsafe fn digest_update() -> super::digest_update_u32::DigestUpdateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIGEST_UPDATE)) }
}

#[inline(always)]
unsafe fn output_digest_final() -> OutputDigestFinalFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OUTPUT_DIGEST_FINAL)) }
}

/// Finalize an HMAC context into `output`.
///
/// # Safety
/// `ctx` must identify a retail HMAC context and `output` must be accepted by
/// its final output transform. No pointer or worker status is validated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hmac_finalize(output: *mut u8, ctx: *mut HmacCtx) {
    let mut inner_digest = [0u8; 20];
    let digest = unsafe { core::ptr::addr_of_mut!((*ctx).digest) };
    let outer_pad = unsafe { core::ptr::addr_of!((*ctx).outer_pad).cast::<u8>() };
    unsafe {
        core_digest_final()(inner_digest.as_mut_ptr(), digest);
        digest_init(digest, (*digest).algorithm);
        digest_update()(outer_pad, digest, OUTER_PAD_LEN);
        digest_update()(inner_digest.as_ptr(), digest, (*digest).state_len);
        output_digest_final()(digest, output);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 5] = [0; 5];
    static mut EVENT_COUNT: usize = 0;
    static mut FINAL_ARGS: [(usize, usize); 2] = [(0, 0); 2];
    static mut UPDATE_ARGS: [(usize, usize, u32); 2] = [(0, 0, 0); 2];

    static mut UPDATE_COUNT: usize = 0;
    unsafe fn event(value: u8) { unsafe { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1 } }
    unsafe extern "C" fn record_core_final(out: *mut u8, ctx: *mut DigestCtx) {
        unsafe { FINAL_ARGS[0] = (out as usize, ctx as usize); event(1) }
        for index in 0..20 { unsafe { *out.add(index) = index as u8 } }
    }
    unsafe extern "C" fn record_update(data: *const u8, ctx: *mut DigestCtx, len: u32) -> i32 {
        unsafe { UPDATE_ARGS[UPDATE_COUNT] = (data as usize, ctx as usize, len); UPDATE_COUNT += 1; event(3) }
        0
    }
    unsafe extern "C" fn record_output_final(ctx: *mut DigestCtx, out: *mut u8) -> u32 {
        unsafe { FINAL_ARGS[1] = (ctx as usize, out as usize); event(5) }
        0
    }

    struct Restore(CoreDigestFinalFn, OutputDigestFinalFn, super::super::digest_update_u32::DigestUpdateFn);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { CORE_DIGEST_FINAL = self.0; OUTPUT_DIGEST_FINAL = self.1; DIGEST_UPDATE = self.2 } }
    }

    #[test]
    fn finalizes_inner_then_outer_digest_for_both_digest_sizes() {
        let _lock = TEST_LOCK.lock();
        let restore = unsafe {
            let restore = Restore(CORE_DIGEST_FINAL, OUTPUT_DIGEST_FINAL, DIGEST_UPDATE);
            CORE_DIGEST_FINAL = record_core_final;
            OUTPUT_DIGEST_FINAL = record_output_final;
            DIGEST_UPDATE = record_update;
            EVENTS = [0; 5]; EVENT_COUNT = 0; UPDATE_COUNT = 0; FINAL_ARGS = [(0, 0); 2]; UPDATE_ARGS = [(0, 0, 0); 2];
            restore
        };
        let mut ctx: HmacCtx = unsafe { core::mem::zeroed() };
        ctx.digest.algorithm = 2;
        ctx.outer_pad = [0x5c; 64];
        let mut output = [0u8; 20];
        unsafe { hmac_finalize(output.as_mut_ptr(), &mut ctx) };
        unsafe {
            assert_eq!(EVENTS, [1, 3, 3, 5, 0]);
            assert_eq!(FINAL_ARGS[0].1, &mut ctx.digest as *mut _ as usize);
            assert_eq!(UPDATE_ARGS[0], (ctx.outer_pad.as_ptr() as usize, &mut ctx.digest as *mut _ as usize, 64));
            assert_eq!(UPDATE_ARGS[1].2, 20);
            assert_eq!(FINAL_ARGS[1], (&mut ctx.digest as *mut _ as usize, output.as_mut_ptr() as usize));
            assert_eq!(*(UPDATE_ARGS[1].0 as *const u8), 0);
            assert_eq!(*(UPDATE_ARGS[1].0 as *const u8).add(19), 19);
        }
        unsafe {
            EVENTS = [0; 5]; EVENT_COUNT = 0; UPDATE_COUNT = 0; UPDATE_ARGS = [(0, 0, 0); 2];
            ctx.digest.algorithm = 1;
            hmac_finalize(output.as_mut_ptr(), &mut ctx);
            assert_eq!(EVENTS, [1, 3, 3, 5, 0]);
            assert_eq!(UPDATE_ARGS[1].2, 16, "kind-1 contexts finalize 16 bytes");
        }
        drop(restore);
    }
}
