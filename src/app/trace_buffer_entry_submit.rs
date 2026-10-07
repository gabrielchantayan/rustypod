//! `trace_buffer_entry_submit` — original: `FUN_0807c724` @ `0x0807c724`
//! (64 bytes; true extent `0x0807c724..0x0807c764`, followed by the distinct
//! `FUN_0807c764`).
//!
//! Raw A32 words contain two unconditional internal `bl` instructions:
//! `trace_buffer_get` at `0x0814a08c` and trace_buffer_install_entry
//! at `0x0814a1c0`; there are no predicated internal calls.
//! Independent whole-image A32 decoding finds four inbound plain `bl` calls
//! (`0x080c68f4`, `0x0813a6b0`, `0x0813a8e0`, and `0x0813a990`) and zero
//! predicated inbound `bl` calls. The wrapper obtains the lazy trace buffer,
//! then forwards its eight opaque words after that buffer to the submitter.
//!
//! Deliberate deviation: Rust call/return replaces the register-save sequence.
//! The submitter now calls the canonical Rust port directly.

/// Submits an opaque eight-word request through the lazily created trace buffer.
///
/// # Safety
///
/// All words must meet the stock trace-buffer submitter's opaque contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn trace_buffer_entry_submit(
    arg1: u32, arg2: u32, arg3: u32, arg4: u32,
    arg5: u32, arg6: u32, arg7: u32, arg8: u32,
) -> u32 {
    unsafe {
        super::trace_buffer_install_entry::trace_buffer_install_entry(
            crate::app::trace_buffer::trace_buffer_get(),
            arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
        )
    }
}

