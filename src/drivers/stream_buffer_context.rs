//! Stream-buffer context initialization wrapper.
//!
//! `stream_buffer_initialize_and_get_page_context` — original:
//! `FUN_08005e5c` @ `0x08005e5c` (28 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/08005e5c_FUN_08005e5c.c`;
//! raw ARM is `0x08005e5c..0x08005e78`.
//!
//! The wrapper first ensures the retailOS stream buffer is initialized through
//! `FUN_08006e88`, then obtains its current page context through
//! `FUN_0800722c`, stores that word through r2, and returns zero. r0 and r1
//! are preserved only as ABI inputs: the ARM body never reads either.

/// The initializer and current-page selector are both local ports.

/// stream_buffer_initialize_and_get_page_context — original: `FUN_08005e5c`
/// @ `0x08005e5c` (28 bytes).
///
/// Initializes the shared stream buffer, gets its current page context, stores
/// it to `page_context_out`, and returns zero. The first two ABI words are
/// deliberately unused, exactly as r0 and r1 are in the ARM wrapper.
///
/// Both dependencies are local ports, so no retailOS dispatch seam remains.
///
/// # Safety
///
/// `page_context_out` must be non-null and valid for one aligned `u32` store.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_initialize_and_get_page_context(
    _unused_first: u32,
    _unused_second: u32,
    page_context_out: *mut u32,
) -> u32 {
    let stream_buffer = crate::kernel::stream_buffer_initializer::initialize_stream_buffer();
    page_context_out.write(crate::kernel::current_page_context::current_page_context(
        stream_buffer,
    ));
    0
}

