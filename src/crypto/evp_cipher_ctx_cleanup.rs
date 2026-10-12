//! EVP cipher-context cleanup, FUN_08049c08 at 0x08049c08.
//!
//! Raw extent: 104 bytes, ending at the independent push at 0x08049c70.
//! Whole-image A32 decode: two inbound plain BLs, no predicated inbound BLs;
//! body: two plain BLs, one BLNE, and one indirect BLX. Call optional cipher
//! cleanup (+0x1c); zero rejects cleanup immediately. Otherwise poison non-NULL
//! cipher_data (+0x60) using the reloaded descriptor's ctx_size (+0x20), then
//! reload and free cipher_data. Without a descriptor, free without poisoning.
//! Finally clear the entire 0x8c-byte context and return 1. No NULL ctx guard.
//!
//! Deviations: repr(C) pointer fields widen host fixtures, retaining target
//! offsets. Use the existing ported heap_poison, traced_free, and memzero_aligned
//! rather than stock BL targets; volatile zero-helper dispatch prevents builtin
//! substitution. Host clearing covers the widened structure, target clearing
//! remains exactly 140 bytes. Callback mutations are observed by volatile reloads.
//!
//! ARM review: match.py reports a structural diff (exit 1): target +0x60,
//! descriptor +0x1c/+0x20, callback rejection, poison/free ordering and
//! 140-byte clear agree. LLVM adds a frame and uses indirect BLX for zeroing.

use crate::drivers::ata_cmd::traced_free;
use crate::heap::heap_poison::heap_poison;
use crate::libc::memzero::memzero_aligned;

#[repr(C)]
pub struct EvpCipher {
    pub header: [u32; 7],
    pub cleanup: Option<unsafe extern "C" fn(*mut EvpCipherCtx) -> i32>,
    pub ctx_size: u32,
}

#[repr(C)]
pub struct EvpCipherCtx {
    pub cipher: *const EvpCipher,
    pub state: [u32; 23],
    pub cipher_data: *mut u8,
    pub tail: [u32; 10],
}

/// # Safety
/// ctx must be writable; descriptor and callback must be valid. Non-NULL
/// cipher_data must satisfy heap_poison and traced_free's contracts. A successful
/// callback must leave a valid descriptor when cipher_data remains non-NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn evp_cipher_ctx_cleanup(ctx: *mut EvpCipherCtx) -> i32 {
    let cipher = core::ptr::addr_of!((*ctx).cipher).read_volatile();
    if !cipher.is_null() {
        if let Some(cleanup) = core::ptr::addr_of!((*cipher).cleanup).read_volatile() {
            if cleanup(ctx) == 0 { return 0; }
        }
        let data = core::ptr::addr_of!((*ctx).cipher_data).read_volatile();
        if !data.is_null() {
            let cipher = core::ptr::addr_of!((*ctx).cipher).read_volatile();
            heap_poison(data, core::ptr::addr_of!((*cipher).ctx_size).read_volatile());
        }
    }
    let data = core::ptr::addr_of!((*ctx).cipher_data).read_volatile();
    if !data.is_null() { traced_free(data); }
    let zero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = memzero_aligned;
    let zero = core::ptr::addr_of!(zero).read_volatile();
    zero(ctx.cast(), core::mem::size_of::<EvpCipherCtx>());
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK, LARGE_ALLOC_TAG};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;

    unsafe extern "C" fn reject(ctx: *mut EvpCipherCtx) -> i32 {
        (*ctx).tail[9] = 0x1234;
        0
    }
    unsafe extern "C" fn replace(ctx: *mut EvpCipherCtx) -> i32 {
        (*ctx).cipher = &REPLACEMENT;
        (*ctx).cipher_data = (*ctx).cipher_data.add(4);
        -1
    }
    static REPLACEMENT: EvpCipher = EvpCipher {
        header: [0; 7], cleanup: None, ctx_size: 3,
    };
    unsafe extern "C" fn verify_release(data: *mut u8) {
        assert_eq!(data.read(), 0x61);
        assert_ne!(data.add(1).read(), 0xa5);
        assert_ne!(data.add(2).read(), 0xa5);
        assert_eq!(data.add(3).read(), 0xa5);
        data.write(0xee);
    }
    unsafe extern "C" fn verify_unpoisoned(data: *mut u8) {
        assert_eq!(data.read(), 0xa5);
        data.write(0xee);
    }
    struct Reset(TracedFreeHooks, u8);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { TRACED_FREE_HOOKS = self.0; LARGE_ALLOC_TAG = self.1; }
        }
    }
    fn context(cipher: *const EvpCipher, data: *mut u8) -> EvpCipherCtx {
        EvpCipherCtx { cipher, state: [0xa5a5a5a5; 23], cipher_data: data,
            tail: [0x55555555; 10] }
    }
    fn assert_cleared(ctx: &EvpCipherCtx) {
        assert!(ctx.cipher.is_null());
        assert!(ctx.cipher_data.is_null());
        assert_eq!(ctx.state, [0; 23]);
        assert_eq!(ctx.tail, [0; 10]);
    }
    #[test]
    fn rejected_callback_preserves_state_and_its_own_mutation() {
        let cipher = EvpCipher { header: [0; 7], cleanup: Some(reject), ctx_size: 8 };
        let mut data = [0xa5; 8];
        let mut ctx = context(&cipher, data.as_mut_ptr());
        assert_eq!(unsafe { evp_cipher_ctx_cleanup(&mut ctx) }, 0);
        assert_eq!(ctx.cipher, &cipher as *const _);
        assert_eq!(ctx.cipher_data, data.as_mut_ptr());
        assert_eq!(ctx.state, [0xa5a5a5a5; 23]);
        assert_eq!(ctx.tail[9], 0x1234);
        assert_eq!(data, [0xa5; 8]);
    }
    #[test]
    fn replacement_is_poisoned_before_release_and_absent_descriptor_skips_poison() {
        let _tag = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _free = TRACED_FREE_TEST_LOCK.lock();
        let _reset = unsafe { Reset(TRACED_FREE_HOOKS, LARGE_ALLOC_TAG) };
        unsafe {
            TRACED_FREE_HOOKS = TracedFreeHooks { free: verify_release, trace: None };
            LARGE_ALLOC_TAG = 0x61;
        }
        let cipher = EvpCipher { header: [0; 7], cleanup: Some(replace), ctx_size: 8 };
        let mut data = [0xa5; 12];
        let mut ctx = context(&cipher, data.as_mut_ptr());
        assert_eq!(unsafe { evp_cipher_ctx_cleanup(&mut ctx) }, 1);
        assert_cleared(&ctx);
        assert_eq!(&data[..4], &[0xa5; 4]);
        assert_eq!(data[4], 0xee);
        assert_eq!(&data[7..], &[0xa5; 5]);
        unsafe { TRACED_FREE_HOOKS.free = verify_unpoisoned; }
        let mut ctx = context(core::ptr::null(), data.as_mut_ptr());
        assert_eq!(unsafe { evp_cipher_ctx_cleanup(&mut ctx) }, 1);
        assert_eq!(data[0], 0xee);
        assert_cleared(&ctx);
    }
    #[test]
    fn missing_data_and_optional_callback_clear_without_release() {
        let cipher = EvpCipher { header: [0; 7], cleanup: None, ctx_size: u32::MAX };
        for descriptor in [core::ptr::null(), &cipher as *const _] {
            let mut ctx = context(descriptor, core::ptr::null_mut());
            assert_eq!(unsafe { evp_cipher_ctx_cleanup(&mut ctx) }, 1);
            assert_cleared(&ctx);
        }
    }
}
