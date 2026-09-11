//! `EVP_DigestUpdate` from the OpenSSL copy Apple vendored into retailOS
//! (crypto/evp/digest.c), NOT the proprietary digest ported in
//! [`crate::crypto::digest_init`].
//!
//! `evp_digest_update` — original: `FUN_0804a728` @ 0x0804a728, 12 bytes
//! (three instruction words, no literal pool: the previous function ends
//! at 0x0804a724 with `bx r1` and the next one — the base64 encoder —
//! starts at 0x0804a734 with `stmdb sp!,{r4,lr}`, so Ghidra's 12 is right
//! for once). 21 call sites, binary-scanned over every branch word in
//! `work/firmware/osos.dec`: 19 plain `bl`, 2 `blgt`, zero plain `b`, and
//! the address appears in no data word — it is never dispatched
//! indirectly.
//!
//! # Body
//!
//! ```text
//! 0804a728:  ldr  r3,[r0,#0x0]    ; r3 = ctx->digest
//! 0804a72c:  ldr  r3,[r3,#0x14]   ; r3 = digest->update
//! 0804a730:  bx   r3              ; tail call update(ctx, data, count)
//! ```
//!
//! One `EVP_MD` slot load and a tail branch. `r0` (ctx), `r1` (data) and
//! `r2` (count) pass through untouched; only `r3` — the unused fourth
//! argument register — is clobbered, which is why every Ghidra call site
//! shows at most three arguments.
//!
//! # Why this is the EVP layer
//!
//! The sibling functions on either side pin both structs exactly, and
//! `EVP_DigestFinal_ex` @ 0x0804a604 carries OpenSSL's own assertion
//! string verbatim at 0x0804a694:
//! `"ctx->digest->md_size <= EVP_MAX_MD_SIZE"`.
//!
//! ```text
//! 0804a564  EVP_DigestVerify-shaped wrapper: 16 bytes of zeroed stack
//!           context (`add sp,sp,#0x10` on the way out), flags |= 1,
//!           then init / update / final / cleanup in that order.
//! 0804a6bc  EVP_DigestInit_ex(ctx, type, impl): clears flag bit 2,
//!           releases the old md_data, stores the new type at ctx+0x00,
//!           allocates type->ctx_size (+0x44) bytes into ctx+0x0c, and
//!           tail-calls type->init (+0x10) with r0=ctx.
//! 0804a728  EVP_DigestUpdate(ctx, data, count)  <- this function.
//! 0804a604  EVP_DigestFinal_ex(ctx, md, size): asserts md_size (+0x08)
//!           <= EVP_MAX_MD_SIZE, calls type->final (+0x18) with r0=ctx
//!           and r1=md, writes md_size through the optional `size`
//!           out-parameter, then calls type->cleanup (+0x20) if present,
//!           sets flag bit 2 and cleanses ctx_size bytes of md_data.
//! ```
//!
//! The 20-byte digests the callers request (`mov r2,#0x14` around the
//! HMAC-shaped loop @ 0x080a40b0) are SHA-1, obtained from the `EVP_MD`
//! getter @ 0x0804b214.
//!
//! # No NULL and no zero-length guard
//!
//! The function dereferences `ctx` unconditionally: there is no `cmp`
//! anywhere in its three words. The two predicated call sites make that
//! explicit — 0x080ebfdc and 0x080ef6c4 both run
//!
//! ```text
//!   ldr  r0,[r4,#0xc]     ; the buffer pointer
//!   cmp  r0,#0x0
//!   cmpne r5,#0x0         ; the byte count
//!   movgt r2,r5
//!   movgt r1,r7
//!   movgt r0,r6
//!   blgt 0x0804a728
//! ```
//!
//! i.e. the caller tests both the buffer and the length and skips the
//! call entirely rather than relying on a guard inside it. A zero
//! `count` that does reach the function is still forwarded to the
//! algorithm's `update`; this port keeps that.
//!
//! # Deliberate host deviation
//!
//! Host pointers are twice the target's 32-bit width, so [`EvpMd`] and
//! [`EvpMdCtx`] place their slots structurally as `#[repr(C)]` fields
//! instead of addressing raw bytes at `+0x14` and `+0x00`. On the
//! `armv5te-none-eabi` target the fields land on the original offsets.
//! [`EVP_MD_UPDATE_SLOT`] keeps the encoded offset checkable against the
//! instruction word regardless.

/// The whole function, as it appears at 0x0804a728 in `osos.dec`.
pub const EVP_DIGEST_UPDATE_BODY: [u32; 3] = [0xe590_3000, 0xe593_3014, 0xe12f_ff13];

/// Byte offset of `update` inside `EVP_MD`, as encoded in the immediate
/// of `ldr r3,[r3,#0x14]`.
pub const EVP_MD_UPDATE_SLOT: u32 = EVP_DIGEST_UPDATE_BODY[1] & 0xfff;

/// The digest algorithm descriptor (`EVP_MD`), as far as the four
/// binary-verified EVP entry points at 0x0804a564..0x0804acb4 pin it.
/// Besides the dispatch slots, `EVP_MD_CTX_cleanup` reads `ctx_size` at
/// +0x44; the eight intervening opaque words retain that target offset
/// without inventing meanings for fields this cluster never reaches.
#[repr(C)]
pub struct EvpMd {
    /// +0x00: algorithm NID. Read by neither of the ported entry points.
    pub type_nid: i32,
    /// +0x04: signing key NID. Likewise unread here.
    pub pkey_type: i32,
    /// +0x08: digest length in bytes, asserted `<= EVP_MAX_MD_SIZE` by
    /// `EVP_DigestFinal_ex` @ 0x0804a604 and reported through its
    /// optional `size` out-parameter.
    pub md_size: i32,
    /// +0x0c: algorithm flags.
    pub flags: u32,
    /// +0x10: tail-called by `EVP_DigestInit_ex` @ 0x0804a6bc.
    pub init: unsafe extern "C" fn(ctx: *mut EvpMdCtx) -> i32,
    /// +0x14: the slot this function dispatches.
    pub update: unsafe extern "C" fn(ctx: *mut EvpMdCtx, data: *const u8, count: u32) -> i32,
    /// +0x18: called by `EVP_DigestFinal_ex` with `r0=ctx`, `r1=md`.
    pub finish: unsafe extern "C" fn(ctx: *mut EvpMdCtx, md: *mut u8) -> i32,
    /// +0x1c: never loaded by any of the four ported entry points, so
    /// its ABI is unobserved and it stays an untyped word.
    pub slot_1c: usize,
    /// +0x20: called by `EVP_DigestFinal_ex` and
    /// `EVP_MD_CTX_cleanup` with `r0=ctx` when non-NULL.
    pub cleanup: Option<unsafe extern "C" fn(ctx: *mut EvpMdCtx) -> i32>,
    /// +0x24..+0x40: descriptor fields not inspected by this EVP cluster.
    pub opaque_24_to_40: [u32; 8],
    /// +0x44: size in bytes of `EvpMdCtx::md_data`.
    pub ctx_size: u32,
}

/// The digest context (`EVP_MD_CTX`). Sixteen bytes on the target — the
/// wrapper @ 0x0804a564 zeroes exactly four words on the stack and pops
/// them with `add sp,sp,#0x10`.
#[repr(C)]
pub struct EvpMdCtx {
    /// +0x00: the algorithm descriptor. The only field this function reads.
    pub digest: *const EvpMd,
    /// +0x04: engine handle. `EVP_DigestInit_ex` accepts an `impl` argument
    /// but the retail body never reads it or stores this field.
    pub engine: *mut u8,
    /// +0x08: flags. Bit 0 marks a one-shot context; bit 1 is set by
    /// `EVP_DigestFinal_ex` and cleared by `EVP_DigestInit_ex`.
    pub flags: u32,
    /// +0x0c: `ctx_size` bytes of per-algorithm state.
    pub md_data: *mut u8,
}

/// `EVP_DigestUpdate(ctx, data, count)` — original: `FUN_0804a728` @
/// 0x0804a728 (12 bytes).
///
/// Feeds `count` bytes at `data` to the algorithm selected by
/// `ctx->digest`, by tail-calling that descriptor's `update` slot with
/// the three arguments unchanged, and returns whatever it returns
/// (non-zero on success, as the callers' `cmp r0,#0x0` tests show).
///
/// # Safety
///
/// There is no guard of any kind in the original: `ctx` must be non-NULL
/// and initialized by `EVP_DigestInit_ex`, so that `ctx->digest` is a
/// readable descriptor with a valid `update` slot. `data` and `count`
/// are passed straight through and are the algorithm's problem.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_digest_update(
    ctx: *mut EvpMdCtx,
    data: *const u8,
    count: u32,
) -> i32 {
    let digest = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).digest));
    ((*digest).update)(ctx, data, count)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static CALLS_LOCK: Mutex<()> = Mutex::new(());

    /// What the dispatched slot saw, and which slot ran at all.
    static mut UPDATE_CALLS: u32 = 0;
    static mut OTHER_SLOT_CALLS: u32 = 0;
    static mut SEEN_CTX: *mut EvpMdCtx = core::ptr::null_mut();
    static mut SEEN_DATA: *const u8 = core::ptr::null();
    static mut SEEN_COUNT: u32 = 0;
    static mut UPDATE_RESULT: i32 = 1;

    unsafe extern "C" fn record_update(ctx: *mut EvpMdCtx, data: *const u8, count: u32) -> i32 {
        UPDATE_CALLS += 1;
        SEEN_CTX = ctx;
        SEEN_DATA = data;
        SEEN_COUNT = count;
        addr_of!(UPDATE_RESULT).read()
    }

    unsafe extern "C" fn record_other_one_arg(_ctx: *mut EvpMdCtx) -> i32 {
        OTHER_SLOT_CALLS += 1;
        0
    }

    unsafe extern "C" fn record_other_two_arg(_ctx: *mut EvpMdCtx, _md: *mut u8) -> i32 {
        OTHER_SLOT_CALLS += 1;
        0
    }

    static SHA1_LIKE: EvpMd = EvpMd {
        type_nid: 64,
        pkey_type: 65,
        md_size: 0x14,
        flags: 0,
        init: record_other_one_arg,
        update: record_update,
        finish: record_other_two_arg,
        slot_1c: 0,
        cleanup: Some(record_other_one_arg),
        opaque_24_to_40: [0; 8],
        ctx_size: 0,
    };

    struct Fixture {
        ctx: EvpMdCtx,
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new(result: i32) -> Self {
            let guard = CALLS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            unsafe {
                addr_of_mut!(UPDATE_CALLS).write(0);
                addr_of_mut!(OTHER_SLOT_CALLS).write(0);
                addr_of_mut!(SEEN_CTX).write(core::ptr::null_mut());
                addr_of_mut!(SEEN_DATA).write(core::ptr::null());
                addr_of_mut!(SEEN_COUNT).write(0);
                addr_of_mut!(UPDATE_RESULT).write(result);
            }
            Fixture {
                ctx: EvpMdCtx {
                    digest: &SHA1_LIKE,
                    engine: core::ptr::null_mut(),
                    flags: 1,
                    md_data: core::ptr::null_mut(),
                },
                _guard: guard,
            }
        }

        fn update(&mut self, data: *const u8, count: u32) -> i32 {
            unsafe { evp_digest_update(&mut self.ctx, data, count) }
        }
    }

    #[test]
    fn forwards_all_three_arguments_to_the_algorithms_update_slot() {
        let mut f = Fixture::new(1);
        let data = [0x11u8, 0x22, 0x33, 0x44];
        let expected_ctx = addr_of_mut!(f.ctx);

        assert_eq!(f.update(data.as_ptr(), data.len() as u32), 1);

        unsafe {
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_CTX).read(), expected_ctx);
            assert_eq!(addr_of!(SEEN_DATA).read(), data.as_ptr());
            assert_eq!(addr_of!(SEEN_COUNT).read(), 4);
        }
    }

    #[test]
    fn dispatches_only_the_update_slot_and_never_a_neighbouring_one() {
        let mut f = Fixture::new(1);
        let data = [0xffu8; 8];

        f.update(data.as_ptr(), 8);

        unsafe {
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert_eq!(
                addr_of!(OTHER_SLOT_CALLS).read(),
                0,
                "init (+0x10), final (+0x18) and cleanup (+0x20) belong to \
                 the sibling entry points, not to this one"
            );
        }
    }

    #[test]
    fn returns_the_slots_result_unchanged_including_failure_and_negatives() {
        // The callers only ever test `== 0`, but nothing here narrows the
        // value, so every bit pattern must survive.
        for result in [0i32, 1, -1, i32::MIN, i32::MAX, 0x7fff_0001] {
            let mut f = Fixture::new(result);
            let byte = 0xa5u8;
            assert_eq!(f.update(&byte, 1), result);
            unsafe { assert_eq!(addr_of!(UPDATE_CALLS).read(), 1) };
        }
    }

    #[test]
    fn a_zero_count_still_reaches_the_algorithm() {
        // The two `blgt` call sites gate on `count > 0` themselves; a zero
        // that does arrive is forwarded, because the three-word body has no
        // comparison in it at all.
        let mut f = Fixture::new(1);
        let data = [0u8; 1];

        assert_eq!(f.update(data.as_ptr(), 0), 1);

        unsafe {
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_COUNT).read(), 0);
        }
    }

    #[test]
    fn the_data_pointer_is_forwarded_verbatim_and_never_dereferenced() {
        // `data` lives in r1 and is untouched by the body, so even NULL
        // travels through to the algorithm exactly as the original does.
        let mut f = Fixture::new(0);

        assert_eq!(f.update(core::ptr::null(), 0x1234_5678), 0);

        unsafe {
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert!(addr_of!(SEEN_DATA).read().is_null());
            assert_eq!(addr_of!(SEEN_COUNT).read(), 0x1234_5678);
        }
    }

    #[test]
    fn a_reassigned_digest_redirects_the_next_call() {
        // `EVP_DigestInit_ex` @ 0x0804a6bc rewrites ctx+0x00; the slot is
        // re-read on every call rather than cached anywhere.
        static mut SECOND_CALLS: u32 = 0;
        unsafe extern "C" fn second_update(
            _ctx: *mut EvpMdCtx,
            _data: *const u8,
            _count: u32,
        ) -> i32 {
            SECOND_CALLS += 1;
            7
        }
        static OTHER: EvpMd = EvpMd {
            type_nid: 4,
            pkey_type: 0,
            md_size: 0x10,
            flags: 0,
            init: record_other_one_arg,
            update: second_update,
            finish: record_other_two_arg,
            slot_1c: 0,
            cleanup: Some(record_other_one_arg),
            opaque_24_to_40: [0; 8],
            ctx_size: 0,
        };

        let mut f = Fixture::new(1);
        let byte = 0x5au8;
        unsafe { addr_of_mut!(SECOND_CALLS).write(0) };

        assert_eq!(f.update(&byte, 1), 1);
        f.ctx.digest = &OTHER;
        assert_eq!(f.update(&byte, 1), 7);

        unsafe {
            assert_eq!(addr_of!(UPDATE_CALLS).read(), 1);
            assert_eq!(addr_of!(SECOND_CALLS).read(), 1);
        }
    }

    #[test]
    fn the_declared_update_slot_matches_the_encoded_offset() {
        assert_eq!(EVP_MD_UPDATE_SLOT, 0x14);
        // ldr r3,[r0,#0] / ldr r3,[r3,#0x14] / bx r3 — and nothing else,
        // which is what makes the missing NULL check a fact rather than a
        // reading of the decompiler.
        assert_eq!(
            EVP_DIGEST_UPDATE_BODY,
            [0xe590_3000, 0xe593_3014, 0xe12f_ff13]
        );
        assert_eq!(EVP_DIGEST_UPDATE_BODY[0] & 0xfff, 0, "ctx->digest is +0x00");
    }
}
