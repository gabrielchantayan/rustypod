//! `dispatch_if_optional_link_valid` — original: `FUN_08046ac8` @
//! `0x08046ac8` (84 bytes; true extent `0x08046ac8..0x08046b1c`, followed by
//! `store_u32_be_bytes` at `0x08046b1c`).
//!
//! Raw ARM contains one plain direct `bl` to `0x080dad3c`, no predicated
//! direct `bl` instructions, and one conditional tail branch to `0x080d189c`.
//! Algorithm: reject a null node, a node with a null first word, or a zero
//! dispatcher; then call the optional-link validator.  A nonzero validator
//! result tail-dispatches the original four arguments, otherwise returns zero.
//! Deliberate deviation: the unported tree dispatcher is exposed as a host
//! seam; ARM retains its retail tail-call contract. Validation uses the Rust port.
use crate::optional_link_allows_dispatch;

/// Performs the unported tree dispatch after validation.
pub type TreeDispatcher = unsafe extern "C" fn(*const u32, u32, *mut u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_tree_dispatcher(_node: *const u32, _dispatcher: u32, _link: *mut u32, _value: u32) -> u32 { 0 }

/// Host-only replacement for retailOS `FUN_080d189c`.
#[cfg(not(target_arch = "arm"))]
pub static mut DISPATCH_IF_OPTIONAL_LINK_VALID_OPS: TreeDispatcher = missing_tree_dispatcher;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_if_optional_link_valid(
    node: *const u32,
    dispatcher: u32,
    link: *mut u32,
    value: u32,
) -> u32 {
    if node.is_null() || (*node).eq(&0) || dispatcher == 0 {
        return 0;
    }
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(DISPATCH_IF_OPTIONAL_LINK_VALID_OPS));
    if optional_link_allows_dispatch(dispatcher, link) == 0 {
        return 0;
    }
    dispatch(node, dispatcher, link, value)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_if_optional_link_valid
    .type dispatch_if_optional_link_valid, %function
dispatch_if_optional_link_valid:
    push    {{r4, r5, r6, r7, r8, lr}}
    movs    r4, r0
    ldrne   r0, [r4]
    mov     r5, r1
    cmpne   r0, #0
    cmpne   r5, #0
    mov     r7, r3
    mov     r6, r2
    beq     1f
    mov     r1, r6
    mov     r0, r5
    bl      optional_link_allows_dispatch
    cmp     r0, #0
    movne   r3, r7
    movne   r2, r6
    movne   r1, r5
    movne   r0, r4
    popne  {{r4, r5, r6, r7, r8, lr}}
    bne     0x080d189c
1:  mov     r0, #0
    pop     {{r4, r5, r6, r7, r8, pc}}
    .size dispatch_if_optional_link_valid, . - dispatch_if_optional_link_valid
"#
);

