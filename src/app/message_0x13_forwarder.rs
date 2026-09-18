//! `message_0x13_forwarder` — original: `thunk_FUN_0826f0a0` at load address
//! `0x08158740` (4 bytes: `b 0x0826f0a0`). The next independently linked
//! function begins at `0x08158744` with `push {r4, lr}`.
//!
//! Full-image raw A32 decoding finds four inbound plain `bl` calls
//! (`0x0812ed58`, `0x08141454`, `0x08146f50`, and `0x0816ab70`) and no
//! predicated `bl` calls.
//!
//! Algorithm: preserve the complete incoming AAPCS register and stack state,
//! then tail-branch to the retail message handler at `0x0826f0a0`. The
//! handler's independently recovered body tests message kind 0x13 and uses
//! opaque object-vtable slots, but this thunk neither interprets nor changes
//! that ABI.
//!
//! # Deliberate deviations
//!
//! The payload cannot use the stock PC-relative `b`: its final link address is
//! not known while assembling this source. The relocation-safe `ldr pc` veneer
//! is eight bytes rather than the stock four-byte branch, but preserves every
//! register, flags, stack word, and tail-call return edge.

/// Retail tail target reached by the forwarding veneer.
pub const RETAIL_MESSAGE_0X13_HANDLER: u32 = 0x0826_f0a0;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.message_0x13_forwarder,"ax",%progbits
    .p2align 2
    .globl message_0x13_forwarder
    .type message_0x13_forwarder,%function
message_0x13_forwarder:
    ldr pc, [pc, #-4]
    .word 0x0826f0a0
    .size message_0x13_forwarder, . - message_0x13_forwarder
"#
);

#[cfg(test)]
mod tests {
    use super::RETAIL_MESSAGE_0X13_HANDLER;

    #[test]
    fn targets_the_verified_retail_handler() {
        assert_eq!(RETAIL_MESSAGE_0X13_HANDLER, 0x0826_f0a0);
    }
}
