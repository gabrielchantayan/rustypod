//! OpenSSL's `EVP_DigestInit_ex` from the retailOS vendored
//! `crypto/evp/digest.c`.
//!
//! `evp_digest_init_ex` — original: `FUN_0804a6bc` @ 0x0804a6bc, 108
//! bytes exactly (0x0804a6bc..0x0804a728). The preceding bytes
//! 0x0804a694..0x0804a6bc are the assertion string
//! `"ctx->digest->md_size <= EVP_MAX_MD_SIZE"`; the separately linked
//! `EVP_DigestUpdate` begins at 0x0804a728.
//!
//! The function clears the finalized bit, replaces a changed descriptor,
//! releases existing per-digest state only when the old descriptor has a
//! nonzero `ctx_size`, allocates the new descriptor's state, then dispatches
//! its `init` slot. Its exact ten direct inbound calls are nine unconditional
//! `bl` (0x0803b530, 0x0804a5ac, 0x0805fd8c, 0x080607dc, 0x08092660,
//! 0x080a40d0, 0x080a41a4, 0x080e7488, and 0x080ebf18) plus one `blne`
//! (0x080ebe90). The predicated caller proves the callee has no NULL guard.
//!
//! # Deliberate deviations
//!
//! The raw body never reads `impl`/r2 or writes `EvpMdCtx::engine`, unlike
//! upstream OpenSSL's ENGINE-aware API; this port retains that retailOS
//! behavior. Shared `#[repr(C)]` fields preserve target offsets only on ARM,
//! where pointers are four bytes. Rust uses ordinary calls rather than the
//! final `bx` tail dispatch, with the same result and callback arguments.

use crate::crypto::evp_digest_update::{EvpMd, EvpMdCtx};
use crate::crypto::evp_md_ctx_cleanup::EVP_MD_CTX_FLAG_CLEANED;
use crate::drivers::ata_cmd::{traced_alloc, traced_free};

/// `EVP_DigestInit_ex(ctx, digest, impl)` — original: `FUN_0804a6bc` @
/// 0x0804a6bc (108 bytes; nine `bl` and one `blne` call sites).
///
/// Clears `EVP_MD_CTX_FLAG_CLEANED`, and only replaces `ctx->digest` when it
/// differs from `digest`. Replacing a nonzero-sized old descriptor frees
/// `ctx->md_data`; a nonzero-sized new descriptor allocates replacement data
/// with `traced_alloc(ctx_size, 0, 0)`. Finally invokes `digest->init(ctx)`
/// even when both descriptor pointers were equal.
///
/// # Safety
///
/// The retail body dereferences `ctx` and `digest` without guards. Both must
/// be valid, and an old non-null descriptor with a nonzero `ctx_size` requires
/// `ctx->md_data` to be acceptable to `traced_free`.
#[cfg_attr(target_os = "none", link_section = ".text.evp_digest_init_ex")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_digest_init_ex(
    ctx: *mut EvpMdCtx,
    digest: *const EvpMd,
    _impl: *mut u8,
) -> i32 {
    let flags = core::ptr::addr_of!((*ctx).flags).read_volatile();
    core::ptr::addr_of_mut!((*ctx).flags).write_volatile(flags & !EVP_MD_CTX_FLAG_CLEANED);

    let old_digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
    if old_digest != digest {
        if !old_digest.is_null()
            && core::ptr::addr_of!((*old_digest).ctx_size).read_volatile() != 0
        {
            let old_data = core::ptr::addr_of!((*ctx).md_data).read_volatile();
            traced_free(old_data);
        }

        core::ptr::addr_of_mut!((*ctx).digest).write_volatile(digest);
        let ctx_size = core::ptr::addr_of!((*digest).ctx_size).read_volatile();
        if ctx_size != 0 {
            let data = traced_alloc(ctx_size as i32, 0, 0);
            core::ptr::addr_of_mut!((*ctx).md_data).write_volatile(data);
        }
    }

    (core::ptr::addr_of!((*digest).init).read())(ctx)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK,
    };
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATED_DATA: [u8; 8] = [0; 8];
    static mut OLD_DATA: [u8; 8] = [0; 8];
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;
    static mut ALLOC_SIZE: i32 = 0;
    static mut ALLOC_TAGS: [u32; 2] = [0; 2];
    static mut FREED: *mut u8 = core::ptr::null_mut();
    static mut INIT_CTX: *mut EvpMdCtx = core::ptr::null_mut();

    unsafe fn event(value: u8) {
        EVENTS[EVENT_COUNT] = value;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        event(2);
        ALLOC_SIZE = size;
        ALLOC_TAGS = [tag1, tag2];
        core::ptr::addr_of_mut!(ALLOCATED_DATA).cast::<u8>()
    }

    unsafe extern "C" fn record_free(block: *mut u8) {
        event(1);
        FREED = block;
    }

    unsafe extern "C" fn old_init(_ctx: *mut EvpMdCtx) -> i32 { -1 }
    unsafe extern "C" fn initialized(ctx: *mut EvpMdCtx) -> i32 {
        event(3);
        INIT_CTX = ctx;
        23
    }
    unsafe extern "C" fn zero_initialized(ctx: *mut EvpMdCtx) -> i32 {
        event(3);
        INIT_CTX = ctx;
        -7
    }
    unsafe extern "C" fn unused_update(
        _ctx: *mut EvpMdCtx,
        _data: *const u8,
        _count: u32,
    ) -> i32 { 0 }
    unsafe extern "C" fn unused_finish(_ctx: *mut EvpMdCtx, _md: *mut u8) -> i32 { 0 }

    static OLD_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: old_init,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: None,
        opaque_24_to_40: [0; 8],
        ctx_size: 8,
    };
    static NEW_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: initialized,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: None,
        opaque_24_to_40: [0; 8],
        ctx_size: 5,
    };
    static ZERO_MD: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: 0,
        flags: 0,
        init: zero_initialized,
        update: unused_update,
        finish: unused_finish,
        slot_1c: 0,
        cleanup: None,
        opaque_24_to_40: [0; 8],
        ctx_size: 0,
    };

    struct HookReset {
        alloc: TracedAllocHooks,
        free: TracedFreeHooks,
    }

    impl Drop for HookReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.alloc);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.free);
            }
        }
    }

    unsafe fn install_hooks() -> HookReset {
        let reset = HookReset {
            alloc: core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS)),
            free: core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)),
        };
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
            TracedAllocHooks { alloc: record_alloc, trace: None },
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
            TracedFreeHooks { free: record_free, trace: None },
        );
        EVENTS = [0; 3];
        EVENT_COUNT = 0;
        ALLOC_SIZE = 0;
        ALLOC_TAGS = [u32::MAX; 2];
        FREED = core::ptr::null_mut();
        INIT_CTX = core::ptr::null_mut();
        reset
    }

    #[test]
    fn replacement_frees_allocates_and_initializes_in_order() {
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = unsafe { install_hooks() };
        let mut ctx = EvpMdCtx {
            digest: &OLD_MD,
            engine: 0x1234usize as *mut u8,
            flags: 0xa5a5_a5a7,
            md_data: core::ptr::addr_of_mut!(OLD_DATA).cast::<u8>(),
        };

        assert_eq!(unsafe { evp_digest_init_ex(&mut ctx, &NEW_MD, 0x5678usize as *mut u8) }, 23);

        unsafe {
            assert_eq!(EVENTS, [1, 2, 3]);
            assert_eq!(FREED, core::ptr::addr_of_mut!(OLD_DATA).cast::<u8>());
            assert_eq!(ALLOC_SIZE, 5);
            assert_eq!(ALLOC_TAGS, [0, 0]);
            assert_eq!(INIT_CTX, core::ptr::addr_of_mut!(ctx));
        }
        assert!(core::ptr::eq(ctx.digest, &NEW_MD));
        assert_eq!(ctx.engine, 0x1234usize as *mut u8, "retailOS ignores impl/r2");
        assert_eq!(ctx.flags, 0xa5a5_a5a5);
        assert_eq!(ctx.md_data, unsafe { core::ptr::addr_of_mut!(ALLOCATED_DATA).cast::<u8>() });
    }

    #[test]
    fn same_descriptor_still_initializes_without_allocator_traffic() {
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = unsafe { install_hooks() };
        let data = core::ptr::addr_of_mut!(OLD_DATA).cast::<u8>();
        let mut ctx = EvpMdCtx {
            digest: &NEW_MD,
            engine: core::ptr::null_mut(),
            flags: EVP_MD_CTX_FLAG_CLEANED,
            md_data: data,
        };

        assert_eq!(unsafe { evp_digest_init_ex(&mut ctx, &NEW_MD, core::ptr::null_mut()) }, 23);

        unsafe {
            assert_eq!(EVENTS, [3, 0, 0]);
            assert!(FREED.is_null());
            assert_eq!(INIT_CTX, core::ptr::addr_of_mut!(ctx));
        }
        assert_eq!(ctx.flags, 0);
        assert_eq!(ctx.md_data, data);
    }

    #[test]
    fn zero_sized_new_descriptor_leaves_existing_data_unchanged() {
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = unsafe { install_hooks() };
        let data = unsafe { core::ptr::addr_of_mut!(OLD_DATA).cast::<u8>() };
        let mut ctx = EvpMdCtx {
            digest: core::ptr::null(),
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: data,
        };

        assert_eq!(unsafe { evp_digest_init_ex(&mut ctx, &ZERO_MD, core::ptr::null_mut()) }, -7);

        unsafe {
            assert_eq!(EVENTS, [3, 0, 0]);
            assert!(FREED.is_null());
            assert_eq!(INIT_CTX, core::ptr::addr_of_mut!(ctx));
        }
        assert!(core::ptr::eq(ctx.digest, &ZERO_MD));
        assert_eq!(ctx.md_data, data, "the raw path does not clear md_data for zero ctx_size");
    }
}
