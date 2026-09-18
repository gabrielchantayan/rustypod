//! filesystem_kind_is_hfsplus — `FUN_0813a318` @ 0x0813a318 (12 bytes).
//!
//! Raw `osos.dec` words establish the 12-byte extent: `cmp r0, #1`,
//! `movne r0, #0`, and `bx lr`; the next independently entered function starts
//! at 0x0813a324. Four inbound direct calls are all unconditional `bl`
//! instructions (0x080fd9d0, 0x080fd9fc, 0x08152258, and 0x08152264); no
//! predicated `bl` calls target this address. The recovered callers pass
//! filesystem kinds 1 (HFS+) and 2 (FAT32), so this returns one only for HFS+.
//!
//! Deliberate deviations: none. The target definition uses raw A32 assembly
//! so this three-instruction BL target remains byte-for-byte structural parity;
//! the host-only Rust definition supplies the same C-ABI behavior to tests.

// Returns one when `filesystem_kind` is the HFS+ kind (one), otherwise zero.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.filesystem_kind_is_hfsplus,"ax",%progbits
    .globl filesystem_kind_is_hfsplus
    .type filesystem_kind_is_hfsplus,%function
filesystem_kind_is_hfsplus:
    cmp r0, #1
    movne r0, #0
    bx lr
    .size filesystem_kind_is_hfsplus, . - filesystem_kind_is_hfsplus
"#
);

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub extern "C" fn filesystem_kind_is_hfsplus(filesystem_kind: u32) -> u32 {
    u32::from(filesystem_kind == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_hfsplus_kind() {
        for (filesystem_kind, expected) in [
            (0u32, 0u32),
            (1, 1),
            (2, 0),
            (0x7fff_ffff, 0),
            (0x8000_0000, 0),
            (u32::MAX, 0),
        ] {
            assert_eq!(
                filesystem_kind_is_hfsplus(filesystem_kind),
                expected,
                "filesystem kind {filesystem_kind:#010x}"
            );
        }
    }
}
