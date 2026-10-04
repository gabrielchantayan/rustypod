//! `context_handle_request` — original: `FUN_0822039c` @ **0x0822039c**.
//!
//! **80 bytes**, `0x0822039c..0x082203ec`; the next real function starts
//! with `push {r4,lr}` at 0x082203ec. Raw words contain two plain outbound
//! BLs (0x082203c8, 0x082203e0), zero predicated BLs. The two inbound BLs
//! (0x08142524, 0x0817a544) are also plain, with zero predicated callers.
//!
//! Resolves an all-ones selector from context+0x89c; flag bit 0 at +0x8a4
//! replaces the requested position with the mode-selected position. Processes
//! the context handle into output, forwarding changed as the fifth argument,
//! discards the processor status, and always returns one. Both callees use
//! their established Rust ports; the processor ignores position and selector.
//! Deliberate deviations: none in behavior. LLVM may eliminate unused argument
//! preparation when the existing processor's ignored arguments are visible.

use crate::app::context_handle_process::context_handle_process;
use crate::app::mode_selected_position::mode_selected_position;

/// # Safety
/// `context` must be four-byte aligned and readable through +0x8a4, and
/// satisfy `context_handle_process`'s object contract. `output` and `changed`
/// must satisfy that processor's output contracts. No NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_handle_request(
    context: *mut u8,
    output: *mut u8,
    mut position: u32,
    changed: *mut u8,
    mut selector: u32,
) -> u32 {
    let flags = context.add(0x8a4).read();
    if selector == u32::MAX {
        selector = context.add(0x89c).cast::<u32>().read();
    }
    if flags & 1 != 0 {
        position = mode_selected_position(context);
    }
    context_handle_process(context, output, position as usize as *mut u8, selector as usize as *mut u8, changed);
    1
}
