//! OpenSSL's one-shot `EVP_Digest` wrapper from retailOS `crypto/evp/digest.c`.
//!
//! `evp_digest` — original: `FUN_0804a564` @ `0x0804a564`, 160 bytes
//! (`0x0804a564..0x0804a604`), ending at the next push-prologue
//! (`EVP_DigestFinal_ex`). Raw ARM decoding establishes four internal plain
//! `bl` calls (init, update, final, cleanup) and no predicated calls. The
//! wrapper has four direct inbound `bl` call sites according to Ghidra.
//!
//! It creates a zeroed 16-byte `EVP_MD_CTX`, marks it one-shot (flag bit 0),
//! initializes it with the requested descriptor and implementation, updates
//! it with the supplied bytes, finalizes into the supplied output and optional
//! size word, then always cleans up the temporary context. It returns one only
//! when all three digest stages return nonzero.
//!
//! # Deliberate deviations
//!
//! Rust names the four stack words as [`EvpMdCtx`] fields and uses ordinary
//! calls rather than the ARM short-circuit branches; on ARM the shared
//! `#[repr(C)]` layout remains the original 16 bytes. The result, callback
//! order, and unconditional cleanup are unchanged.

use core::ptr;

use crate::crypto::evp_digest_final_ex::evp_digest_final_ex;
use crate::crypto::evp_digest_init_ex::evp_digest_init_ex;
use crate::crypto::evp_digest_update::{evp_digest_update, EvpMd, EvpMdCtx};
use crate::crypto::evp_md_ctx_cleanup::evp_md_ctx_cleanup;

/// `EVP_Digest(data, count, md, size, type, impl)` — original:
/// `FUN_0804a564` @ `0x0804a564` (160 bytes).
///
/// Uses a temporary one-shot digest context. Cleanup executes after an init,
/// update, or final failure as well as after success.
///
/// # Safety
///
/// This keeps retailOS's unchecked contract: `digest` must be a valid
/// descriptor, and `data`, `md`, and `size` must satisfy the selected digest
/// callbacks whenever their corresponding stage is reached.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_digest(
    data: *const u8,
    count: u32,
    md: *mut u8,
    size: *mut u32,
    digest: *const EvpMd,
    implementation: *mut u8,
) -> i32 {
    let mut context = EvpMdCtx {
        digest: ptr::null(),
        engine: ptr::null_mut(),
        flags: 1,
        md_data: ptr::null_mut(),
    };

    let result = if evp_digest_init_ex(&mut context, digest, implementation) == 0
        || evp_digest_update(&mut context, data, count) == 0
        || evp_digest_final_ex(&mut context, md, size) == 0
    {
        0
    } else {
        1
    };
    evp_md_ctx_cleanup(&mut context);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static CALLS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 4] = [0; 4];
    static mut CALL_COUNT: usize = 0;
    static mut UPDATE_DATA: *const u8 = ptr::null();
    static mut UPDATE_COUNT: u32 = 0;
    static mut STAGE_RESULT: [i32; 3] = [1; 3];

    unsafe extern "C" fn record_init(_context: *mut EvpMdCtx) -> i32 {
        CALLS[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        STAGE_RESULT[0]
    }

    unsafe extern "C" fn record_update(
        _context: *mut EvpMdCtx,
        data: *const u8,
        count: u32,
    ) -> i32 {
        CALLS[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        UPDATE_DATA = data;
        UPDATE_COUNT = count;
        STAGE_RESULT[1]
    }

    unsafe extern "C" fn record_finish(_context: *mut EvpMdCtx, output: *mut u8) -> i32 {
        CALLS[CALL_COUNT] = 3;
        CALL_COUNT += 1;
        *output = 0xa5;
        STAGE_RESULT[2]
    }

    unsafe extern "C" fn record_cleanup(_context: *mut EvpMdCtx) -> i32 {
        CALLS[CALL_COUNT] = 4;
        CALL_COUNT += 1;
        1
    }

    static DESCRIPTOR: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 1,
        flags: 0,
        init: record_init,
        update: record_update,
        finish: record_finish,
        slot_1c: 0,
        cleanup: Some(record_cleanup),
        opaque_24_to_40: [0; 8],
        ctx_size: 0,
    };

    fn reset(stage_result: [i32; 3]) {
        unsafe {
            CALLS = [0; 4];
            CALL_COUNT = 0;
            UPDATE_DATA = ptr::null();
            UPDATE_COUNT = 0;
            STAGE_RESULT = stage_result;
        }
    }

    #[test]
    fn forwards_empty_input_and_cleans_up_after_success() {
        let _lock = CALLS_LOCK.lock();
        reset([1, 1, 1]);
        let mut output = 0;
        let mut output_len = 0;
        let result = unsafe {
            evp_digest(
                ptr::null(),
                0,
                &mut output,
                &mut output_len,
                &DESCRIPTOR,
                ptr::null_mut(),
            )
        };

        unsafe {
            assert_eq!(result, 1);
            assert_eq!(CALLS, [1, 2, 3, 4]);
            assert_eq!(UPDATE_DATA, ptr::null());
            assert_eq!(UPDATE_COUNT, 0);
        }
        assert_eq!(output, 0xa5);
        assert_eq!(output_len, 1);
    }

    #[test]
    fn stops_at_failed_stage_but_always_cleans_up() {
        let _lock = CALLS_LOCK.lock();
        let input = [0x7b];
        for (stages, expected_calls) in [([0, 1, 1], [1, 4, 0, 0]), ([1, 0, 1], [1, 2, 4, 0]), ([1, 1, 0], [1, 2, 3, 4])] {
            reset(stages);
            let mut output = 0;
            let result = unsafe {
                evp_digest(input.as_ptr(), 1, &mut output, ptr::null_mut(), &DESCRIPTOR, ptr::null_mut())
            };
            unsafe {
                assert_eq!(result, 0);
                assert_eq!(CALLS, expected_calls);
            }
        }
    }
}
