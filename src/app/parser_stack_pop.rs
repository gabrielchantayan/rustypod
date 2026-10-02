//! `parser_stack_pop` — original: `FUN_0811ddc0` @ `0x0811ddc0` (60 bytes;
//! `0x0811ddc0..0x0811ddfc`).
//!
//! Raw ARM establishes the boundary: `0x0811ddfc` begins with `cmp r0, #0`.
//! Three plain inbound BLs (0x08117e80, 0x08119a24, 0x08119a48), zero
//! predicated inbound BLs; body has one direct BL to parser_stack_item and
//! one register-indirect BLX through vtable slot +0x2c.
//!
//! Retrieves the item at count - 1, then calls vtable slot 11 to remove it.
//! Returns the saved item, discarding the removal result. Deliberate deviation:
//! native-width repr(C) pointers on hosts; ARM retains count +4 and slot +0x2c.

use super::parser_stack_item::{parser_stack_item, ParserStack};

/// Returns and removes the parser stack's final item.
///
/// # Safety
/// `stack` must address a ParserStack with valid lookup and removal methods.
/// The removal method must accept count.wrapping_sub(1), including -1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_stack_pop(stack: *mut u8) -> *mut u8 {
    let stack = stack.cast::<ParserStack>();
    let index = (*stack).count.wrapping_sub(1);
    let item = parser_stack_item(stack, index);
    let remove: unsafe extern "C" fn(*mut ParserStack, i32) =
        core::mem::transmute((*stack).vtable.add(11).read());
    remove(stack, index);
    item
}
