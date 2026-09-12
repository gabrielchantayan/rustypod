//! The four-word initializer for the retailOS vendored OpenSSL EVP context.
//!
//! `evp_md_ctx_init` — original: `FUN_0804adc4` @ 0x0804adc4, 20 bytes
//! exactly (0x0804adc4..0x0804add8). Decoding every ARM B/BL word in
//! `osos.dec` finds eight direct inbound `bl` calls, all unconditional:
//! 0x0803b4c0, 0x0804afa4, 0x0804b0e0, 0x0805fb4c, 0x08060674, 0x08092634,
//! 0x080a3fac, and 0x080e7450. There are no predicated direct calls or tail
//! branches. Each caller passes a 16-byte stack `EvpMdCtx` that subsequently
//! flows through the neighboring EVP init/update/final/cleanup entry points.
//!
//! The body loads zero into r1/r2, writes four aligned words to `ctx`, and
//! returns with r0 advanced by eight bytes because the first `stmia` writes
//! back. The established EVP call pattern identifies this as
//! `EVP_MD_CTX_init` [INFERENCE]; its output register is not observed by any
//! caller. This port preserves that incidental r0 result as a `*mut u32`.
//!
//! # Deliberate deviations
//!
//! `EvpMdCtx` uses named `#[repr(C)]` fields so pointer fields have their
//! target offsets on ARM without overlapping on 64-bit hosts. Individual
//! volatile stores retain all four target writes; unlike the raw `stmia`, the
//! Rust source does not express their paired-store instruction selection.

use crate::crypto::evp_digest_update::EvpMdCtx;

/// Initializes an `EVP_MD_CTX` — original: `FUN_0804adc4` @ 0x0804adc4
/// (20 bytes; eight unconditional direct `bl` call sites).
///
/// Clears the context's descriptor, engine, flags, and per-digest data fields.
/// The ARM post-increment sequence leaves r0 equal to `ctx` plus two words;
/// callers ignore that value, but this return preserves the firmware ABI.
///
/// # Safety
///
/// `ctx` must be non-NULL, aligned, and writable for a complete `EvpMdCtx`.
#[cfg_attr(target_os = "none", link_section = ".text.evp_md_ctx_init")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn evp_md_ctx_init(ctx: *mut EvpMdCtx) -> *mut u32 {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx).digest), core::ptr::null());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx).engine), core::ptr::null_mut());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx).flags), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx).md_data), core::ptr::null_mut());
    ctx.cast::<u32>().add(2)
}

#[cfg(test)]
mod tests {
    use super::evp_md_ctx_init;
    use crate::crypto::evp_digest_update::{EvpMd, EvpMdCtx};

    #[test]
    fn clears_every_context_field_and_preserves_raw_writeback_result() {
        let mut ctx = EvpMdCtx {
            digest: core::ptr::dangling::<EvpMd>(),
            engine: core::ptr::dangling_mut::<u8>(),
            flags: u32::MAX,
            md_data: core::ptr::dangling_mut::<u8>(),
        };
        let start = core::ptr::addr_of_mut!(ctx);

        let returned = unsafe { evp_md_ctx_init(start) };

        assert!(ctx.digest.is_null());
        assert!(ctx.engine.is_null());
        assert_eq!(ctx.flags, 0);
        assert!(ctx.md_data.is_null());
        assert_eq!(returned, start.cast::<u32>().wrapping_add(2));
    }

    #[test]
    fn overwrites_noncanonical_word_patterns() {
        let mut ctx = EvpMdCtx {
            digest: 0xffff_fffcusize as *const EvpMd,
            engine: 0x8000_0000usize as *mut u8,
            flags: 0x7fff_ffff,
            md_data: 1usize as *mut u8,
        };

        unsafe { evp_md_ctx_init(core::ptr::addr_of_mut!(ctx)) };

        assert!(ctx.digest.is_null());
        assert!(ctx.engine.is_null());
        assert_eq!(ctx.flags, 0);
        assert!(ctx.md_data.is_null());
    }
}
