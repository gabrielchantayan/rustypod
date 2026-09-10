//! `EVP_MD_CTX_cleanup` from the OpenSSL copy Apple vendored into retailOS.
//!
//! `evp_md_ctx_cleanup` — original: `FUN_0804ac2c` @ 0x0804ac2c, 136
//! bytes exactly. The preceding bytes 0x0804ac0c..0x0804ac28 are an
//! assertion string's trailing literal data; the next independently linked
//! function begins at 0x0804acb4 (`push {r3,r4,r5,r6,r7,lr}`). A complete
//! raw `osos.dec` ARM B/BL decode finds 11 inbound direct calls, all plain
//! unconditional `bl` (no predicated direct call or direct tail `b`).
//!
//! # Algorithm
//!
//! For a non-NULL `ctx->digest`, call its optional `cleanup` slot (+0x20)
//! unless flags bit 1 is set. Reload `ctx->digest` after that callback; when
//! it still exists and declares a nonzero `ctx_size` (+0x44), poison and free
//! non-NULL `md_data` unless flags bit 2 marks that data borrowed. The
//! `md_data` pointer is reloaded after poisoning before it reaches
//! `traced_free`, exactly as the ARM body does. Finally zero all four context
//! words and return 1. `ctx` itself has no NULL guard: the first instruction
//! is `ldr r0,[r0]`.
//!
//! # Deliberate host/codegen deviation
//!
//! [`EvpMd`] and [`EvpMdCtx`] retain their target slots as `#[repr(C)]` named
//! fields rather than host byte offsets; their pointer fields are naturally
//! 8 bytes on the host and 4 bytes on armv5te. The final four stores are
//! volatile to retain the original's ordered word clears and avoid LLVM
//! lowering them to an unavailable memclear helper; the resulting memory
//! effect is unchanged.

use crate::crypto::evp_digest_update::EvpMdCtx;
#[cfg(test)]
use crate::crypto::evp_digest_update::EvpMd;
use crate::drivers::ata_cmd::traced_free;
use crate::heap::heap_poison::heap_poison;

/// `ctx->flags` bit 1: the algorithm cleanup callback already ran.
pub const EVP_MD_CTX_FLAG_CLEANED: u32 = 2;
/// `ctx->flags` bit 2: `md_data` is externally owned and must not be released.
pub const EVP_MD_CTX_FLAG_MD_DATA_BORROWED: u32 = 4;

/// `EVP_MD_CTX_cleanup` — original: `FUN_0804ac2c` @ 0x0804ac2c (136 bytes;
/// 11 direct unconditional `bl` callers).
///
/// Releases a digest context's owned algorithm state, then clears all four
/// words of the context and returns 1. The optional descriptor cleanup runs
/// before the state release, and its writes to `digest`, `md_data`, or flags
/// are observed by the later reloads.
///
/// # Safety
///
/// `ctx` must be non-NULL, readable and writable. Any non-NULL descriptor,
/// cleanup slot, and owned `md_data` must meet the contracts of their called
/// functions; the retail body dereferences each without an internal guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn evp_md_ctx_cleanup(ctx: *mut EvpMdCtx) -> i32 {
    let digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
    if !digest.is_null() {
        if let Some(cleanup) = core::ptr::addr_of!((*digest).cleanup).read_volatile() {
            let flags = core::ptr::addr_of!((*ctx).flags).read_volatile();
            if flags & EVP_MD_CTX_FLAG_CLEANED == 0 {
                cleanup(ctx);
            }
        }

        // The callback can replace (or clear) ctx->digest.
        let digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
        if !digest.is_null() {
            let ctx_size = core::ptr::addr_of!((*digest).ctx_size).read_volatile();
            if ctx_size != 0 {
                let md_data = core::ptr::addr_of!((*ctx).md_data).read_volatile();
                if !md_data.is_null() {
                    let flags = core::ptr::addr_of!((*ctx).flags).read_volatile();
                    if flags & EVP_MD_CTX_FLAG_MD_DATA_BORROWED == 0 {
                        heap_poison(md_data, ctx_size);
                        // `heap_poison` is allowed to mutate the context through an
                        // alias, and the ARM reloads +0x0c before calling free.
                        let md_data = core::ptr::addr_of!((*ctx).md_data).read_volatile();
                        traced_free(md_data);
                    }
                }
            }
        }
    }

    core::ptr::addr_of_mut!((*ctx).digest).write_volatile(core::ptr::null());
    core::ptr::addr_of_mut!((*ctx).engine).write_volatile(core::ptr::null_mut());
    core::ptr::addr_of_mut!((*ctx).flags).write_volatile(0);
    core::ptr::addr_of_mut!((*ctx).md_data).write_volatile(core::ptr::null_mut());
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedFreeHooks, LARGE_ALLOC_TAG, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK,
    };
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CLEANUP_CALLS: u32 = 0;
    static mut FREE_CALLS: u32 = 0;
    static mut FREED: *mut u8 = core::ptr::null_mut();
    static mut INITIAL_DATA: [u8; 8] = [0; 8];
    static mut REPLACED_DATA: [u8; 8] = [0; 8];

    unsafe extern "C" fn unused_init(_ctx: *mut EvpMdCtx) -> i32 { 1 }
    unsafe extern "C" fn unused_update(_ctx: *mut EvpMdCtx, _data: *const u8, _count: u32) -> i32 { 1 }
    unsafe extern "C" fn unused_finish(_ctx: *mut EvpMdCtx, _md: *mut u8) -> i32 { 1 }

    unsafe extern "C" fn count_cleanup(_ctx: *mut EvpMdCtx) -> i32 {
        CLEANUP_CALLS += 1;
        0
    }

    unsafe extern "C" fn replace_context(ctx: *mut EvpMdCtx) -> i32 {
        CLEANUP_CALLS += 1;
        (*ctx).digest = &REPLACED_MD;
        (*ctx).md_data = core::ptr::addr_of_mut!(REPLACED_DATA).cast::<u8>();
        0
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        FREE_CALLS += 1;
        FREED = block;
    }

    static CLEANUP_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: unused_init,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: Some(count_cleanup),
        opaque_24_to_40: [0; 8],
        ctx_size: 3,
    };

    static INITIAL_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: unused_init,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: Some(replace_context),
        opaque_24_to_40: [0; 8],
        ctx_size: 0,
    };

    static REPLACED_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: unused_init,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: None,
        opaque_24_to_40: [0; 8],
        ctx_size: 3,
    };

    struct HookReset {
        hooks: TracedFreeHooks,
        tag: u8,
    }

    impl Drop for HookReset {
        fn drop(&mut self) {
            unsafe {
                TRACED_FREE_HOOKS = self.hooks;
                LARGE_ALLOC_TAG = self.tag;
            }
        }
    }

    fn install() -> HookReset {
        unsafe {
            let reset = HookReset {
                hooks: core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)),
                tag: core::ptr::read_volatile(core::ptr::addr_of!(LARGE_ALLOC_TAG)),
            };
            TRACED_FREE_HOOKS = TracedFreeHooks { free: record_free, trace: None };
            LARGE_ALLOC_TAG = 0x61;
            CLEANUP_CALLS = 0;
            FREE_CALLS = 0;
            FREED = core::ptr::null_mut();
            INITIAL_DATA = [0xa5; 8];
            REPLACED_DATA = [0; 8];
            reset
        }
    }

    #[test]
    fn cleanup_callback_reloads_context_before_releasing_replacement_data() {
        let _tag_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = install();
        let mut ctx = EvpMdCtx {
            digest: &INITIAL_MD,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: core::ptr::addr_of_mut!(INITIAL_DATA).cast::<u8>(),
        };

        assert_eq!(unsafe { evp_md_ctx_cleanup(&mut ctx) }, 1);

        unsafe {
            assert_eq!(CLEANUP_CALLS, 1);
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(FREED, core::ptr::addr_of_mut!(REPLACED_DATA).cast::<u8>());
            assert_eq!(INITIAL_DATA, [0xa5; 8], "the replaced data pointer is the only one released");
            assert_eq!(REPLACED_DATA[0], 0x61, "heap_poison runs before traced_free");
        }
        assert!(ctx.digest.is_null());
        assert!(ctx.engine.is_null());
        assert_eq!(ctx.flags, 0);
        assert!(ctx.md_data.is_null());
    }

    #[test]
    fn cleaned_and_borrowed_flags_gate_their_distinct_actions() {
        let _tag_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = install();

        let mut finalized = EvpMdCtx {
            digest: &CLEANUP_MD,
            engine: core::ptr::null_mut(),
            flags: EVP_MD_CTX_FLAG_CLEANED,
            md_data: core::ptr::addr_of_mut!(INITIAL_DATA).cast::<u8>(),
        };
        assert_eq!(unsafe { evp_md_ctx_cleanup(&mut finalized) }, 1);
        unsafe {
            assert_eq!(CLEANUP_CALLS, 0, "bit 1 suppresses only the callback");
            assert_eq!(FREE_CALLS, 1, "finalized data remains owned");
            assert_eq!(INITIAL_DATA[0], 0x61);
            CLEANUP_CALLS = 0;
            FREE_CALLS = 0;
            FREED = core::ptr::null_mut();
            INITIAL_DATA = [0xa5; 8];
        }

        let mut borrowed = EvpMdCtx {
            digest: &CLEANUP_MD,
            engine: core::ptr::null_mut(),
            flags: EVP_MD_CTX_FLAG_MD_DATA_BORROWED,
            md_data: core::ptr::addr_of_mut!(INITIAL_DATA).cast::<u8>(),
        };
        assert_eq!(unsafe { evp_md_ctx_cleanup(&mut borrowed) }, 1);
        unsafe {
            assert_eq!(CLEANUP_CALLS, 1, "borrowed state does not suppress descriptor cleanup");
            assert_eq!(FREE_CALLS, 0, "bit 2 retains borrowed md_data");
            assert_eq!(INITIAL_DATA, [0xa5; 8]);
        }
    }

    #[test]
    fn null_digest_skips_all_release_work_but_still_zeroes_context() {
        let _tag_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = install();
        let mut ctx = EvpMdCtx {
            digest: core::ptr::null(),
            engine: 1usize as *mut u8,
            flags: 0xffff_ffff,
            md_data: core::ptr::addr_of_mut!(INITIAL_DATA).cast::<u8>(),
        };

        assert_eq!(unsafe { evp_md_ctx_cleanup(&mut ctx) }, 1);

        unsafe {
            assert_eq!(CLEANUP_CALLS, 0);
            assert_eq!(FREE_CALLS, 0);
            assert_eq!(INITIAL_DATA, [0xa5; 8]);
        }
        assert!(ctx.digest.is_null());
        assert!(ctx.engine.is_null());
        assert_eq!(ctx.flags, 0);
        assert!(ctx.md_data.is_null());
    }
}
