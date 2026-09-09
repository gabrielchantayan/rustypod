//! Byte-block checksum continuation veneer — `thunk_FUN_0802c03c` @
//! 0x08003510 (8 bytes; Ghidra reports 4, dropping the literal-pool word).
//!
//! ```text
//! 08003510  ldr pc, [pc, #-4]      @ tail-branch through the literal below
//! 08003514  .word 0x0802c03c       @ byte-block checksum continuation
//! ```
//!
//! The true extent is 8 bytes: the next literal veneer (`ldr pc, [pc, #-4]`
//! -> 0x08360030) opens at 0x08003518. This is a genuine literal veneer
//! (`0xe51ff004` + target word), not Ghidra's four-byte indirect-call model.
//!
//! ## Call sites (binary-verified)
//!
//! Decoding every ARM B/BL word in `osos.dec` (load base 0x08000000) gives
//! **18** direct call sites, all unconditional `bl`; there are no predicated
//! `bl` forms and no direct `b` sites. The calls are at 0x0800214c,
//! 0x080021f8, 0x08002270, 0x080022e0, 0x08002404, 0x08002414, 0x08002498,
//! 0x08002b30, 0x08002b4c, 0x08002b60, 0x08002b74, 0x08002ba0, 0x080062c4,
//! 0x0800641c, 0x08007cdc, 0x08007ce4, 0x08007d0c, and 0x08007d1c.
//!
//! ## Algorithm and deviation
//!
//! The veneer copies no data and changes no register: it loads PC from the
//! literal so execution continues at 0x0802c03c with the original caller's
//! LR, registers, and stack. That target is an interior, stack-sensitive
//! continuation in the byte-block checksum reader: it uses r7 and local slots
//! at `sp + 0x24..=0x30`, then removes a 0x34-byte frame and pops
//! `{r4-r7, pc}`. It is therefore not a normal Rust ABI call and must not be
//! routed through the existing Rust helper for that continuation.
//!
//! On ARM, global assembly preserves the two original words exactly. A host
//! cannot represent the retail stack transfer or map the retail target, so the
//! host counterpart terminates rather than pretending to return; its test
//! verifies that deliberate non-returning behavior.

/// Fixed ARM instruction at 0x08003510: `ldr pc, [pc, #-4]`.
pub const BYTE_BLOCK_CHECKSUM_VENEER_INSN: u32 = 0xe51f_f004;

/// Literal target at 0x08003514: the stack-sensitive checksum continuation.
pub const BYTE_BLOCK_CHECKSUM_VENEER_TARGET: u32 = 0x0802_c03c;

#[cfg(target_arch = "arm")]
extern "C" {
    /// tail_dispatch_byte_block_checksum_continuation — original:
    /// `thunk_FUN_0802c03c` @ 0x08003510 (8 bytes; 18 unconditional `bl`
    /// call sites).
    ///
    /// Performs the literal tail branch without changing any incoming
    /// registers or caller-frame bytes. The target consumes the surrounding
    /// parser continuation frame and never returns to this immediate call
    /// edge.
    ///
    /// Deviation: none on ARM; this is the original instruction and literal.
    pub fn tail_dispatch_byte_block_checksum_continuation() -> !;
}

/// Host-only stand-in for the stack-sensitive ARM tail dispatch.
///
/// The retail continuation is unmapped on hosts and returns by consuming a
/// caller-specific ARM frame. A normal host call cannot preserve that ABI, so
/// this intentionally terminates rather than introducing a false return path.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
fn unavailable_byte_block_checksum_continuation() -> ! {
    unreachable!("byte-block checksum continuation tail target unavailable on host")
}

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_dispatch_byte_block_checksum_continuation() -> ! {
    unavailable_byte_block_checksum_continuation()
}

// The ARM implementation is deliberately a literal tail branch. `ldr pc`
// retains LR, so the continuation's frame unwind selects its actual return
// destination rather than returning to a Rust wrapper.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_dispatch_byte_block_checksum_continuation
    .type tail_dispatch_byte_block_checksum_continuation, %function
tail_dispatch_byte_block_checksum_continuation:
    ldr     pc, [pc, #-4]
    .word   0x0802c03c
    .size tail_dispatch_byte_block_checksum_continuation, . - tail_dispatch_byte_block_checksum_continuation
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "byte-block checksum continuation tail target unavailable on host")]
    fn host_stand_in_does_not_invent_a_return_edge() {
        unavailable_byte_block_checksum_continuation();
    }

    #[test]
    fn veneer_words_match_the_retail_literal_dispatch() {
        assert_eq!(BYTE_BLOCK_CHECKSUM_VENEER_INSN, 0xe51f_f004);
        assert_eq!(BYTE_BLOCK_CHECKSUM_VENEER_TARGET, 0x0802_c03c);
    }
}
