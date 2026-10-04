//! `context_handle_process_forward` — original: `FUN_0820a4a0` @ **0x0820a4a0**.
//!
//! **28 bytes**, `0x0820a4a0..0x0820a4bc`; the next entry is a separate
//! branch veneer to 0x0822b060. Raw words verify **one plain outbound BL**
//! (0x0820a4b4 to 0x0822af94), zero predicated BLs, and two plain inbound
//! BLs (0x08101360 and 0x081751e8), zero predicated inbound BLs.
//!
//! Forwards all five ABI arguments to `context_handle_process`, including
//! the fifth stack argument, and preserves its return value. The ARM body
//! saves r3 in ip while copying the caller's stack argument into the outgoing
//! slot. Deliberate deviation: Rust calls the existing semantic port directly;
//! LLVM may tail-call it rather than reproducing the stack shuffle.

use crate::app::context_handle_process::context_handle_process;

/// # Safety
/// All arguments must satisfy `context_handle_process`'s contracts. The third
/// and fourth arguments are unused by that callee and need not be dereferenceable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_handle_process_forward(
    context: *mut u8,
    output: *mut u8,
    unused_2: *mut u8,
    unused_3: *mut u8,
    changed: *mut u8,
) -> u32 {
    context_handle_process(context, output, unused_2, unused_3, changed)
}
