//! OpenSSL's `EVP_DigestFinal_ex` from `crypto/evp/digest.c`.
//!
//! `evp_digest_final_ex` — original: `FUN_0804a604` @ 0x0804a604, 144
//! instruction bytes (0x0804a604..0x0804a694). The adjacent bytes
//! 0x0804a694..0x0804a6bc are the assertion string
//! `"ctx->digest->md_size <= EVP_MAX_MD_SIZE"`; the independently linked
//! `EVP_DigestInit_ex` begins at 0x0804a6bc. A raw-image decode of every ARM
//! B/BL immediate finds 11 inbound calls, all unconditional `bl` (at
//! 0x0804a5dc, 0x0804afc0, 0x0804b0fc, 0x0805fd50, 0x0806077c, 0x080926dc,
//! 0x080a4148, 0x080a41e4, 0x080e74c4, 0x080e74dc, and 0x080ebf88), with no
//! predicated calls or tail `b` calls. No aligned image data word equals the
//! entry address, so there is no discovered indirect dispatch.
//!
//! # Algorithm
//!
//! The function rejects a signed `ctx->digest->md_size` greater than
//! `EVP_MAX_MD_SIZE` (36) through the fatal `heap_panic_entry` path. It calls
//! the descriptor's required `finish` slot (+0x18), reloads the descriptor to
//! write its `md_size` (+0x08) through the optional output pointer, then
//! reloads it again for the optional `cleanup` slot (+0x20). A present cleanup
//! sets context flag bit 1. Finally it reloads both descriptor and context,
//! and clears `ctx_size` (+0x44) bytes at `md_data` through the IRAM memzero
//! veneer in the original. Every reload is observable when a callback mutates
//! the context.
//!
//! # Deliberate deviation
//!
//! Host pointers are wider than ARM pointers, so the shared `#[repr(C)]`
//! [`EvpMd`] and [`EvpMdCtx`] use named fields rather than literal byte
//! offsets; on `armv5te-none-eabi` those fields have the target offsets.

use crate::crypto::evp_digest_update::EvpMdCtx;
#[cfg(test)]
use crate::crypto::evp_digest_update::EvpMd;
use crate::heap::veneers::heap_panic_entry;
use crate::libc::iram_veneers::iram_memzero_veneer;

const EVP_MAX_MD_SIZE: i32 = 36;

/// `EVP_DigestFinal_ex(ctx, md, size)` — original: `FUN_0804a604` @
/// 0x0804a604 (144 bytes).
///
/// Finalizes the selected digest into `md`, optionally returns the current
/// descriptor's raw `md_size` through `size`, invokes its optional cleanup,
/// marks the context finalized when that cleanup exists, and clears the
/// descriptor-sized private state. The `finish` return value is preserved.
///
/// # Safety
///
/// As in retailOS, `ctx` and its initial `digest` must be non-NULL and valid;
/// `finish` must be callable, `md` must satisfy that implementation, and a
/// non-NULL `size` must point to a writable word. Any descriptor or context
/// installed by `finish` or `cleanup` must remain valid through subsequent
/// reloads. `md_data` must be writable for the reloaded descriptor's
/// `ctx_size` bytes.
#[cfg_attr(target_os = "none", link_section = ".text.evp_digest_final_ex")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_digest_final_ex(
    ctx: *mut EvpMdCtx,
    md: *mut u8,
    size: *mut u32,
) -> i32 {
    let digest = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).digest));
    if core::ptr::read_volatile(core::ptr::addr_of!((*digest).md_size)) > EVP_MAX_MD_SIZE {
        heap_panic_entry();
    }

    let finish = core::ptr::read_volatile(core::ptr::addr_of!((*digest).finish));
    let result = finish(ctx, md);

    if !size.is_null() {
        let digest = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).digest));
        size.write(core::ptr::read_volatile(core::ptr::addr_of!((*digest).md_size)) as u32);
    }

    let digest = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).digest));
    let cleanup = core::ptr::read_volatile(core::ptr::addr_of!((*digest).cleanup));
    if let Some(cleanup) = cleanup {
        cleanup(ctx);
        let flags = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).flags));
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx).flags), flags | 2);
    }

    let digest = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).digest));
    let ctx_size = core::ptr::read_volatile(core::ptr::addr_of!((*digest).ctx_size));
    let md_data = core::ptr::read_volatile(core::ptr::addr_of!((*ctx).md_data));
    iram_memzero_veneer(md_data, ctx_size as usize);

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static CALLS_LOCK: Mutex<()> = Mutex::new(());
    static mut FINISH_CALLS: u32 = 0;
    static mut CLEANUP_CALLS: u32 = 0;
    static mut SEEN_CTX: *mut EvpMdCtx = core::ptr::null_mut();
    static mut SEEN_MD: *mut u8 = core::ptr::null_mut();
    static mut FINISH_RESULT: i32 = 1;
    static mut REPLACED_DATA: [u8; 3] = [0x9a, 0xbc, 0xde];

    unsafe extern "C" fn record_finish(ctx: *mut EvpMdCtx, md: *mut u8) -> i32 {
        FINISH_CALLS += 1;
        SEEN_CTX = ctx;
        SEEN_MD = md;
        addr_of!(FINISH_RESULT).read()
    }

    unsafe extern "C" fn record_cleanup(_ctx: *mut EvpMdCtx) -> i32 {
        CLEANUP_CALLS += 1;
        0
    }

    unsafe extern "C" fn finish_by_replacing_context(ctx: *mut EvpMdCtx, md: *mut u8) -> i32 {
        record_finish(ctx, md);
        (*ctx).digest = &REPLACED_DESCRIPTOR;
        (*ctx).md_data = addr_of_mut!(REPLACED_DATA).cast();
        addr_of!(FINISH_RESULT).read()
    }

    static STANDARD_DESCRIPTOR: EvpMd = EvpMd {
        type_nid: 64,
        pkey_type: 65,
        md_size: 4,
        flags: 0,
        init: record_cleanup,
        update: unreachable_update,
        finish: record_finish,
        slot_1c: 0,
        cleanup: Some(record_cleanup),
        opaque_24_to_40: [0; 8],
        ctx_size: 4,
    };

    static NO_CLEANUP_DESCRIPTOR: EvpMd = EvpMd {
        type_nid: 0,
        pkey_type: 0,
        md_size: -1,
        flags: 0,
        init: record_cleanup,
        update: unreachable_update,
        finish: record_finish,
        slot_1c: 0,
        cleanup: None,
        opaque_24_to_40: [0; 8],
        ctx_size: 2,
    };

    static REPLACED_DESCRIPTOR: EvpMd = EvpMd {
        type_nid: 4,
        pkey_type: 0,
        md_size: 3,
        flags: 0,
        init: record_cleanup,
        update: unreachable_update,
        finish: record_finish,
        slot_1c: 0,
        cleanup: Some(record_cleanup),
        opaque_24_to_40: [0; 8],
        ctx_size: 3,
    };

    static REPLACING_FINISH_DESCRIPTOR: EvpMd = EvpMd {
        type_nid: 4,
        pkey_type: 0,
        md_size: 4,
        flags: 0,
        init: record_cleanup,
        update: unreachable_update,
        finish: finish_by_replacing_context,
        slot_1c: 0,
        cleanup: Some(record_cleanup),
        opaque_24_to_40: [0; 8],
        ctx_size: 1,
    };

    unsafe extern "C" fn unreachable_update(
        _ctx: *mut EvpMdCtx,
        _data: *const u8,
        _count: u32,
    ) -> i32 {
        panic!("EVP_DigestFinal_ex must not call the update slot")
    }

    fn reset(result: i32) {
        unsafe {
            addr_of_mut!(FINISH_CALLS).write(0);
            addr_of_mut!(CLEANUP_CALLS).write(0);
            addr_of_mut!(SEEN_CTX).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_MD).write(core::ptr::null_mut());
            addr_of_mut!(FINISH_RESULT).write(result);
            addr_of_mut!(REPLACED_DATA).write([0x9a, 0xbc, 0xde]);
        }
    }

    #[test]
    fn finishes_writes_size_cleans_state_and_preserves_result() {
        let _guard = CALLS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset(-1);
        let mut state = [0x11u8, 0x22, 0x33, 0x44];
        let mut output = [0u8; 4];
        let mut size = 0u32;
        let mut ctx = EvpMdCtx {
            digest: &STANDARD_DESCRIPTOR,
            engine: core::ptr::null_mut(),
            flags: 1,
            md_data: state.as_mut_ptr(),
        };

        assert_eq!(unsafe { evp_digest_final_ex(&mut ctx, output.as_mut_ptr(), &mut size) }, -1);

        unsafe {
            assert_eq!(addr_of!(FINISH_CALLS).read(), 1);
            assert_eq!(addr_of!(CLEANUP_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_CTX).read(), addr_of_mut!(ctx));
            assert_eq!(addr_of!(SEEN_MD).read(), output.as_mut_ptr());
        }
        assert_eq!(size, 4);
        assert_eq!(ctx.flags, 3);
        assert_eq!(state, [0; 4]);
    }

    #[test]
    fn absent_cleanup_leaves_flag_unchanged_and_null_size_is_accepted() {
        let _guard = CALLS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset(0);
        let mut state = [0x55u8, 0xaa];
        let mut ctx = EvpMdCtx {
            digest: &NO_CLEANUP_DESCRIPTOR,
            engine: core::ptr::null_mut(),
            flags: 0x8000_0001,
            md_data: state.as_mut_ptr(),
        };

        assert_eq!(unsafe { evp_digest_final_ex(&mut ctx, core::ptr::null_mut(), core::ptr::null_mut()) }, 0);

        unsafe {
            assert_eq!(addr_of!(FINISH_CALLS).read(), 1);
            assert_eq!(addr_of!(CLEANUP_CALLS).read(), 0);
        }
        assert_eq!(ctx.flags, 0x8000_0001);
        assert_eq!(state, [0; 2]);
    }

    #[test]
    fn finish_context_replacement_controls_later_size_cleanup_and_clear() {
        let _guard = CALLS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset(7);
        let mut original_state = [0x77u8];
        let mut output = [0u8; 4];
        let mut size = 0u32;
        let mut ctx = EvpMdCtx {
            digest: &REPLACING_FINISH_DESCRIPTOR,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: original_state.as_mut_ptr(),
        };

        assert_eq!(unsafe { evp_digest_final_ex(&mut ctx, output.as_mut_ptr(), &mut size) }, 7);

        unsafe {
            assert_eq!(addr_of!(FINISH_CALLS).read(), 1);
            assert_eq!(addr_of!(CLEANUP_CALLS).read(), 1);
            assert_eq!(addr_of!(REPLACED_DATA).read(), [0; 3]);
        }
        assert_eq!(size, 3, "size is reloaded after the finish callback");
        assert_eq!(ctx.flags, 2);
        assert_eq!(original_state, [0x77], "clear uses the reloaded md_data");
    }

    #[test]
    fn negative_md_size_is_written_as_its_unmodified_word() {
        let _guard = CALLS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset(1);
        let mut state = [0x44u8, 0x55];
        let mut size = 0u32;
        let mut ctx = EvpMdCtx {
            digest: &NO_CLEANUP_DESCRIPTOR,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: state.as_mut_ptr(),
        };

        assert_eq!(unsafe { evp_digest_final_ex(&mut ctx, core::ptr::null_mut(), &mut size) }, 1);
        assert_eq!(size, u32::MAX);
    }
}
