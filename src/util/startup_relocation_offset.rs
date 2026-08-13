//! Startup image-relocation offset helper from retailOS.
//!
//! `startup_relocation_offset` — original: `FUN_080088d8` @ 0x080088d8
//! (16 bytes), recovered from `decomp/c/000/080088d8_FUN_080088d8.c` and the
//! corresponding `osos.asm` routine. The ARM code materializes its own linked
//! address with `sub r0, pc, #8`, subtracts it from the literal-pool address
//! 0x220088d8, and returns the resulting relocation offset. Thus it reports
//! the offset from the linked retailOS image to its IRAM startup placement:
//! `0x220088d8 - 0x080088d8 = 0x1a000000`.

/// Returns the retailOS startup image's IRAM relocation offset.
///
/// The original's ARM ABI has no arguments and returns this unsigned word in
/// `r0`. Rust uses an explicit linked address because this port is linked at a
/// different address from the retailOS image.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn startup_relocation_offset() -> u32 {
    const LINKED_ROUTINE_ADDRESS: u32 = 0x0800_88d8;
    const RELOCATED_ROUTINE_ADDRESS: u32 = 0x2200_88d8;

    RELOCATED_ROUTINE_ADDRESS.wrapping_sub(LINKED_ROUTINE_ADDRESS)
}

#[cfg(test)]
mod tests {
    use super::startup_relocation_offset;

    #[test]
    fn returns_offset_between_linked_and_iram_startup_addresses() {
        let reference = 0x2200_88d8u32.wrapping_sub(0x0800_88d8);

        assert_eq!(startup_relocation_offset(), reference);
        assert_eq!(startup_relocation_offset(), 0x1a00_0000);
    }
}
