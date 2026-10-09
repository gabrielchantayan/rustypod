//! Default-context retail operation wrapper.
//!
//! Port: [`default_context_operation`] — original: `FUN_08093d64` @
//! **0x08093d64** (8 bytes exactly, `0x08093d64..0x08093d6b`); the literal
//! pool word at `0x08093d6c` is not code, and `0x08093d70` starts a sibling.
//! Raw decoding is `ldr r1, [pc, #0]` / `b 0x080bd7f8`: no body `bl`
//! instructions, predicated or otherwise. There are exactly three direct,
//! unconditional `bl` callers (0x0805ca54, 0x080aafe0, and 0x08113808) and no
//! predicated caller.
//!
//! # Algorithm
//!
//! Preserve r0, supply the fixed filename at `0x083e8bc8`, then resolve it
//! under iPod_Control\\iTunes using the ported helper, returning its status.
//! The stock tail branch becomes a Rust call. Host calls require the fixed
//! firmware filename to be mapped, just as other firmware literal readers.

const DEFAULT_CONTEXT_WORD: usize = 0x083e_8bc8;


/// Forwards `argument` and the fixed retail context word to the helper.
///
/// # Safety
///
/// `argument`, when non-NULL, must permit 258 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_context_operation(argument: *mut u8) -> i32 {
    crate::app::itunes_path_resolve::itunes_path_resolve(argument, DEFAULT_CONTEXT_WORD as *const u8)
}

