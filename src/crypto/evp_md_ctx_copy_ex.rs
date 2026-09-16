//! `EVP_MD_CTX_copy_ex` from the OpenSSL copy Apple vendored into retailOS.
//!
//! `evp_md_ctx_copy_ex` — original: `FUN_0804acb4` @ 0x0804acb4, 204 bytes
//! exactly. Extent confirmed from raw bytes: 0x0804acb4..0x0804ad80; the
//! next independently linked function starts at 0x0804ad80 with
//! `push {r4,lr}`, so Ghidra's 204 is right. Call count binary-verified
//! against `decomp/osos.asm` and the raw BL decode: exactly 5 inbound
//! sites, ALL plain unconditional `bl` (0x0804afb0, 0x0804b0ec,
//! 0x0805fcc8, 0x08060748, 0x080ebf2c) - no predicated calls, no tail `b`.
//!
//! # Algorithm
//!
//! Copy a digest context `src` into `ctx`. If `src` is NULL or carries a
//! NULL `digest`, log `diag_ring_record(ERR_LIB_EVP=6,
//! EVP_F_EVP_MD_CTX_COPY_EX=110, EVP_R_INPUT_NOT_INITIALIZED=111, 0, 0)`
//! and return 0, leaving `ctx` untouched. When both contexts already share
//! the same descriptor, the old `md_data` is saved and `ctx->flags` gains
//! bit 2 (OpenSSL's REUSE) BEFORE `evp_md_ctx_cleanup` runs, so cleanup
//! treats the state buffer as borrowed and keeps it; otherwise the saved
//! pointer is NULL and cleanup releases any old state. The four context
//! words are then copied from `src` with a 16-byte `ldmia`/`stmia`. When
//! the (freshly copied) descriptor declares a nonzero `ctx_size` (+0x44),
//! the saved buffer is restored into `ctx->md_data`, or
//! `traced_alloc(ctx_size, 0, 0)` provides a new one, and `ctx_size` bytes
//! move from `src->md_data` through the `__rt_memcpy` IRAM veneer. Finally,
//! when the descriptor's +0x1c copy slot is non-NULL, the function TAIL
//! CALLS `copy(ctx, src)` and returns its value; otherwise it returns 1.
//!
//! # Deliberate host/codegen deviation
//!
//! Target offsets use `#[repr(C)]` named fields ([`EvpMd`], [`EvpMdCtx`])
//! because host pointers are 8 bytes; the four-word context copy is four
//! volatile field copies. The descriptor, `ctx_size`, `md_data`, and the
//! copy slot are re-read after the cleanup callback and after
//! `traced_alloc`, matching the ARM reloads. The +0x1c slot stays an
//! untyped word in [`EvpMd`] (no other ported descriptor user types it);
//! it is transmuted to `copy(ctx, src)` only after the non-NULL test.

use crate::crypto::evp_digest_update::{EvpMd, EvpMdCtx};
use crate::crypto::evp_md_ctx_cleanup::evp_md_ctx_cleanup;
use crate::drivers::ata_cmd::traced_alloc;
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::rt_memcpy::__rt_memcpy;

/// OpenSSL `ERR_LIB_EVP`: the facility word of the NULL-source diagnostic.
pub const ERR_LIB_EVP: u32 = 6;
/// OpenSSL `EVP_F_EVP_MD_CTX_COPY_EX`: the subsystem word of the diagnostic.
pub const EVP_F_EVP_MD_CTX_COPY_EX: u32 = 110;
/// OpenSSL `EVP_R_INPUT_NOT_INITIALIZED`: the code word of the diagnostic.
pub const EVP_R_INPUT_NOT_INITIALIZED: u32 = 111;

/// `ctx->flags` bit 2 in its REUSE role: the destination already holds a
/// buffer for this same algorithm, so cleanup must not release it. This is
/// the same bit `evp_md_ctx_cleanup` reads as
/// `EVP_MD_CTX_FLAG_MD_DATA_BORROWED`.
pub const EVP_MD_CTX_FLAG_REUSE: u32 = 4;

/// `EVP_MD_CTX_copy_ex(ctx, src)` — original: `FUN_0804acb4` @ 0x0804acb4
/// (204 bytes; 5 direct unconditional `bl` callers).
///
/// Makes `ctx` a copy of `src`, reusing `ctx`'s existing state buffer when
/// both contexts use the same digest algorithm. Returns 1 on success (or
/// the descriptor copy callback's value when one is installed), 0 when
/// `src` is NULL or uninitialized.
///
/// # Safety
///
/// `ctx` must be non-NULL, readable and writable. A non-NULL `src` must be
/// a readable context whose `digest` descriptor (when non-NULL) exposes
/// valid `ctx_size` (+0x44) and, when nonzero, a readable `src->md_data`
/// of that many bytes; a non-NULL +0x1c copy slot must be a callable
/// `copy(ctx, src)`. The retail body dereferences all of these without
/// internal guards, and does not check the `traced_alloc` result.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn evp_md_ctx_copy_ex(ctx: *mut EvpMdCtx, src: *const EvpMdCtx) -> i32 {
    if src.is_null() || core::ptr::addr_of!((*src).digest).read_volatile().is_null() {
        diag_ring_record(
            ERR_LIB_EVP,
            EVP_F_EVP_MD_CTX_COPY_EX,
            EVP_R_INPUT_NOT_INITIALIZED,
            0,
            0,
        );
        return 0;
    }

    let src_digest = core::ptr::addr_of!((*src).digest).read_volatile();
    let mut saved_md_data: *mut u8 = core::ptr::null_mut();
    if core::ptr::addr_of!((*ctx).digest).read_volatile() == src_digest {
        let flags = core::ptr::addr_of!((*ctx).flags).read_volatile();
        saved_md_data = core::ptr::addr_of!((*ctx).md_data).read_volatile();
        core::ptr::addr_of_mut!((*ctx).flags).write_volatile(flags | EVP_MD_CTX_FLAG_REUSE);
    }

    evp_md_ctx_cleanup(ctx);

    // The ARM moves all four context words with ldmia r5,{r1,r2,r3,r7} /
    // stmia r4,{r1,r2,r3,r7}; on the host each field is copied on its own.
    core::ptr::addr_of_mut!((*ctx).digest).write_volatile(core::ptr::addr_of!((*src).digest).read_volatile());
    core::ptr::addr_of_mut!((*ctx).engine).write_volatile(core::ptr::addr_of!((*src).engine).read_volatile());
    core::ptr::addr_of_mut!((*ctx).flags).write_volatile(core::ptr::addr_of!((*src).flags).read_volatile());
    core::ptr::addr_of_mut!((*ctx).md_data).write_volatile(core::ptr::addr_of!((*src).md_data).read_volatile());

    let digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
    let ctx_size = core::ptr::addr_of!((*digest).ctx_size).read_volatile();
    if ctx_size != 0 {
        if !saved_md_data.is_null() {
            core::ptr::addr_of_mut!((*ctx).md_data).write_volatile(saved_md_data);
        } else {
            let fresh = traced_alloc(ctx_size as i32, 0, 0);
            core::ptr::addr_of_mut!((*ctx).md_data).write_volatile(fresh);
        }
        // Reloaded after the allocator call, exactly as the ARM body does.
        let digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
        let src_data = core::ptr::addr_of!((*src).md_data).read_volatile();
        let ctx_size = core::ptr::addr_of!((*digest).ctx_size).read_volatile();
        let dst_data = core::ptr::addr_of!((*ctx).md_data).read_volatile();
        __rt_memcpy(dst_data, src_data, ctx_size as usize);
    }

    let digest = core::ptr::addr_of!((*ctx).digest).read_volatile();
    let copy = core::ptr::addr_of!((*digest).slot_1c).read_volatile();
    if copy != 0 {
        let copy: unsafe extern "C" fn(ctx: *mut EvpMdCtx, src: *const EvpMdCtx) -> i32 =
            core::mem::transmute(copy);
        return copy(ctx, src);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::crypto::evp_md_ctx_cleanup::EVP_MD_CTX_FLAG_MD_DATA_BORROWED;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK,
    };
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_REQUEST: Option<(i32, u32, u32)> = None;
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut FREED: *mut u8 = core::ptr::null_mut();
    static mut DIAG_RING: *mut DiagEventRing = core::ptr::null_mut();
    static mut COPY_CALLS: Option<(*mut EvpMdCtx, *const EvpMdCtx)> = None;
    static mut CLEANUP_FLAGS: u32 = 0;

    unsafe extern "C" fn unused_init(_ctx: *mut EvpMdCtx) -> i32 { 1 }
    unsafe extern "C" fn unused_update(_ctx: *mut EvpMdCtx, _data: *const u8, _count: u32) -> i32 { 1 }
    unsafe extern "C" fn unused_finish(_ctx: *mut EvpMdCtx, _md: *mut u8) -> i32 { 1 }

    unsafe extern "C" fn recording_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        unsafe {
            ALLOC_REQUEST = Some((size, tag1, tag2));
            ALLOC_RESULT
        }
    }

    unsafe extern "C" fn recording_free(block: *mut u8) {
        unsafe { FREED = block };
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        unsafe { DIAG_RING }
    }

    unsafe extern "C" fn record_cleanup_flags(ctx: *mut EvpMdCtx) -> i32 {
        unsafe { CLEANUP_FLAGS = (*ctx).flags };
        1
    }

    unsafe extern "C" fn record_copy(ctx: *mut EvpMdCtx, src: *const EvpMdCtx) -> i32 {
        unsafe { COPY_CALLS = Some((ctx, src)) };
        42
    }

    unsafe extern "C" fn failing_copy(_ctx: *mut EvpMdCtx, _src: *const EvpMdCtx) -> i32 { 0 }

    static mut COPY_SLOT: usize = 0;

    fn make_digest(ctx_size: u32, with_copy_slot: bool) -> EvpMd {
        EvpMd {
            type_nid: 0,
            pkey_type: 0,
            md_size: 0,
            flags: 0,
            init: unused_init,
            update: unused_update,
            finish: unused_finish,
            slot_1c: if with_copy_slot { unsafe { COPY_SLOT } } else { 0 },
            cleanup: None,
            opaque_24_to_40: [0; 8],
            ctx_size,
        }
    }

    fn empty_ctx() -> EvpMdCtx {
        EvpMdCtx {
            digest: core::ptr::null(),
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: core::ptr::null_mut(),
        }
    }

    struct Fixture {
        _test_guard: MutexGuard<'static, ()>,
        _diag_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        _free_guard: parking_lot::MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_free_hooks: TracedFreeHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        ring: Box<DiagEventRing>,
    }

    impl Fixture {
        fn new() -> Self {
            let test_guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let free_guard = TRACED_FREE_TEST_LOCK.lock();
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_REQUEST = None;
                ALLOC_RESULT = core::ptr::null_mut();
                FREED = core::ptr::null_mut();
                COPY_CALLS = None;
                CLEANUP_FLAGS = 0;
                COPY_SLOT = record_copy as usize;
                DIAG_RING = ring.as_mut();
                let saved_alloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_free_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
                let saved_ring_getter = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: recording_alloc, trace: None },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                    TracedFreeHooks { free: recording_free, trace: None },
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), Some(ring_getter));
                Self {
                    _test_guard: test_guard,
                    _diag_guard: diag_guard,
                    _alloc_guard: alloc_guard,
                    _free_guard: free_guard,
                    saved_alloc_hooks,
                    saved_free_hooks,
                    saved_ring_getter,
                    ring,
                }
            }
        }

        fn ring_record_count(&self) -> u32 {
            // A fresh ring has head == tail == 0; each record advances head.
            unsafe { core::ptr::addr_of!((*self.ring.as_ref()).head).read_volatile() as u32 }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.saved_alloc_hooks);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.saved_free_hooks);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), self.saved_ring_getter);
                ALLOC_RESULT = core::ptr::null_mut();
                ALLOC_REQUEST = None;
                FREED = core::ptr::null_mut();
                COPY_CALLS = None;
                COPY_SLOT = 0;
                DIAG_RING = core::ptr::null_mut();
            }
        }
    }

    #[test]
    fn null_src_logs_and_returns_zero_without_touching_ctx() {
        let _fixture = Fixture::new();
        let sentinel_md = make_digest(8, false);
        let mut data = [0xa5u8; 8];
        let mut ctx = EvpMdCtx {
            digest: &sentinel_md,
            engine: core::ptr::null_mut(),
            flags: 0x10,
            md_data: data.as_mut_ptr(),
        };
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, core::ptr::null()) };
        assert_eq!(result, 0);
        assert_eq!(ctx.flags, 0x10);
        assert_eq!(ctx.digest, &sentinel_md as *const EvpMd);
        assert_eq!(ctx.md_data, data.as_mut_ptr());
        assert_eq!(_fixture.ring_record_count(), 1);
        assert!(unsafe { ALLOC_REQUEST }.is_none());
        assert!(unsafe { FREED }.is_null());
    }

    #[test]
    fn src_with_null_digest_logs_and_returns_zero() {
        let _fixture = Fixture::new();
        let src = empty_ctx();
        let mut ctx = empty_ctx();
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 0);
        assert!(ctx.digest.is_null());
        assert_eq!(_fixture.ring_record_count(), 1);
    }

    #[test]
    fn copy_into_empty_ctx_allocates_and_copies_state() {
        let _fixture = Fixture::new();
        let md = make_digest(8, false);
        let mut src_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut src = EvpMdCtx {
            digest: &md,
            engine: 0xdeadbeefusize as *mut u8,
            flags: 0x21,
            md_data: src_data.as_mut_ptr(),
        };
        let mut backing = [0u8; 8];
        unsafe { ALLOC_RESULT = backing.as_mut_ptr() };
        let mut ctx = empty_ctx();
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 1);
        assert_eq!(ctx.digest, &md as *const EvpMd);
        assert_eq!(ctx.engine, src.engine);
        assert_eq!(ctx.flags, 0x21);
        assert_eq!(ctx.md_data, backing.as_mut_ptr());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((8, 0, 0)));
        assert_eq!(backing, src_data);
        assert!(unsafe { FREED }.is_null());
        src.md_data = core::ptr::null_mut();
    }

    #[test]
    fn same_digest_reuses_existing_state_buffer() {
        let _fixture = Fixture::new();
        let mut md = make_digest(8, false);
        md.cleanup = Some(record_cleanup_flags);
        let mut src_data = [9u8; 8];
        let mut dst_data = [0u8; 8];
        let src = EvpMdCtx {
            digest: &md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: src_data.as_mut_ptr(),
        };
        let mut ctx = EvpMdCtx {
            digest: &md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: dst_data.as_mut_ptr(),
        };
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 1);
        // Cleanup observed the REUSE bit set before it ran.
        assert_eq!(unsafe { CLEANUP_FLAGS } & EVP_MD_CTX_FLAG_REUSE, EVP_MD_CTX_FLAG_REUSE);
        // Same buffer kept, no alloc, no free, contents copied.
        assert_eq!(ctx.md_data, dst_data.as_mut_ptr());
        assert_eq!(dst_data, src_data);
        assert!(unsafe { ALLOC_REQUEST }.is_none());
        assert!(unsafe { FREED }.is_null());
    }

    #[test]
    fn different_digest_frees_old_state_and_allocates_new() {
        let _fixture = Fixture::new();
        let old_md = make_digest(8, false);
        let new_md = make_digest(8, false);
        let mut old_data = [0u8; 8];
        let mut src_data = [0x5au8; 8];
        let mut backing = [0u8; 8];
        unsafe { ALLOC_RESULT = backing.as_mut_ptr() };
        let mut ctx = EvpMdCtx {
            digest: &old_md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: old_data.as_mut_ptr(),
        };
        let src = EvpMdCtx {
            digest: &new_md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: src_data.as_mut_ptr(),
        };
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 1);
        assert_eq!(unsafe { FREED }, old_data.as_mut_ptr());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((8, 0, 0)));
        assert_eq!(ctx.md_data, backing.as_mut_ptr());
        assert_eq!(backing, src_data);
    }

    #[test]
    fn borrowed_old_state_is_kept_by_cleanup_but_replaced_by_copy() {
        let _fixture = Fixture::new();
        let old_md = make_digest(8, false);
        let new_md = make_digest(8, false);
        let mut old_data = [0u8; 8];
        let mut src_data = [0x77u8; 8];
        let mut backing = [0u8; 8];
        unsafe { ALLOC_RESULT = backing.as_mut_ptr() };
        let mut ctx = EvpMdCtx {
            digest: &old_md,
            engine: core::ptr::null_mut(),
            flags: EVP_MD_CTX_FLAG_MD_DATA_BORROWED,
            md_data: old_data.as_mut_ptr(),
        };
        let src = EvpMdCtx {
            digest: &new_md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: src_data.as_mut_ptr(),
        };
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 1);
        // Bit 2 suppressed the free inside cleanup; the buffer is dropped
        // only because the four-word copy overwrites md_data.
        assert!(unsafe { FREED }.is_null());
        assert_eq!(ctx.md_data, backing.as_mut_ptr());
        assert_eq!(backing, src_data);
    }

    #[test]
    fn zero_ctx_size_skips_alloc_and_memcpy() {
        let _fixture = Fixture::new();
        let md = make_digest(0, false);
        let mut src_data = [0x11u8; 4];
        let src = EvpMdCtx {
            digest: &md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: src_data.as_mut_ptr(),
        };
        let mut ctx = empty_ctx();
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 1);
        // md_data is the copied pointer; no allocation happened.
        assert_eq!(ctx.md_data, src_data.as_mut_ptr());
        assert!(unsafe { ALLOC_REQUEST }.is_none());
    }

    #[test]
    fn copy_slot_is_tail_called_and_its_result_returned() {
        let _fixture = Fixture::new();
        let md = make_digest(0, true);
        let src = EvpMdCtx {
            digest: &md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: core::ptr::null_mut(),
        };
        let mut ctx = empty_ctx();
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 42);
        let (seen_ctx, seen_src) = unsafe { COPY_CALLS }.expect("copy slot not called");
        assert_eq!(seen_ctx, &mut ctx as *mut EvpMdCtx);
        assert_eq!(seen_src, &src as *const EvpMdCtx);
    }

    #[test]
    fn copy_slot_failure_propagates() {
        let _fixture = Fixture::new();
        let mut md = make_digest(0, true);
        unsafe { COPY_SLOT = failing_copy as usize };
        md.slot_1c = unsafe { COPY_SLOT };
        let src = EvpMdCtx {
            digest: &md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: core::ptr::null_mut(),
        };
        let mut ctx = empty_ctx();
        let result = unsafe { evp_md_ctx_copy_ex(&mut ctx, &src) };
        assert_eq!(result, 0);
    }
}
