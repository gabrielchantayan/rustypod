//! Port of the control-state flags getter `FUN_08292e6c` @ 0x08292e6c
//! (20 bytes, 253 `bl` call sites in osos).
//!
//! Original:
//!
//! ```text
//! ldr r0, [0x8292e80]      ; literal 0x089cc928 — control-state object base
//! ldr r0, [r0, #0x4]       ; flags word @ 0x089cc92c
//! mov r0, r0, lsl #0x14
//! mov r0, r0, lsr #0x14    ; keep low 12 bits
//! bx  lr
//! ```
//!
//! A packed-field getter: the word at 0x089cc92c (offset +4 of the
//! control-subsystem state object @ 0x089cc928) carries a 12-bit flags
//! field in its low bits; this returns exactly that field
//! (`word & 0xFFF`). Callers test individual bits — e.g. the mode gate
//! `flags & 0x10` @ 0x081f6344 — and the sibling setter @ 0x08292e84
//! stores the full word back (using bit 0x4000 as a "conditional store"
//! sentinel that is above this mask and therefore never visible through
//! the getter). Neighbors @ 0x08292c10..0x08292e64 drive a UI
//! "controller" switch (vtable dispatch; "CntrlHistoryFn" string @
//! 0x08292c9c), saving these flags, forcing 0x10, and restoring —
//! which is what the control_state naming records; the individual flag
//! bits' meanings remain with the (unported) writers of 0x089cc92c.
//!
//! # Deviation
//!
//! On target the flags word is read straight from the original firmware
//! address 0x089cc92c (the field belongs to the still-unported control
//! subsystem, so the port must not own a copy — cf. the static-model
//! convention in sync_mutex.rs, which applies only to port-owned
//! globals). Host builds substitute a mock word (`set_mock_flags_word`)
//! so the mask behavior is testable. Codegen on ARM is the same
//! load-and-mask leaf as the original.

#[cfg(not(target_arch = "arm"))]
use core::ptr::{addr_of, addr_of_mut};

/// Firmware address of the flags word: `*0x089cc928 + 4` in the original
/// (literal-pool base pointer plus the `ldr [r0, #0x4]` offset).
#[cfg(target_arch = "arm")]
const FLAGS_WORD_ADDR: u32 = 0x089c_c92c;

/// Mask applied by the original's `lsl #20; lsr #20` pair.
const FLAGS_MASK: u32 = 0xFFF;

/// Host-test stand-in for the firmware flags word @ 0x089cc92c.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_FLAGS_WORD: u32 = 0;

/// Host only: install the word the getter will read.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_flags_word(word: u32) {
    *addr_of_mut!(MOCK_FLAGS_WORD) = word;
}

#[inline]
fn flags_word() -> u32 {
    #[cfg(target_arch = "arm")]
    unsafe {
        (FLAGS_WORD_ADDR as *const u32).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_FLAGS_WORD)
    }
}

/// Original: `FUN_08292e6c` @ 0x08292e6c (20 bytes) — returns the low
/// 12 bits of the control-state flags word @ 0x089cc92c.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn control_state_flags() -> u32 {
    flags_word() & FLAGS_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_all_twelve_low_bits_through() {
        unsafe {
            for bits in [0x000u32, 0x001, 0x010, 0x555, 0xAAA, 0xFFF] {
                set_mock_flags_word(bits);
                assert_eq!(control_state_flags(), bits);
            }
        }
    }

    #[test]
    fn masks_everything_above_bit11() {
        unsafe {
            // Setter's 0x4000 conditional-store sentinel is above the
            // mask: invisible through the getter.
            set_mock_flags_word(0x4000);
            assert_eq!(control_state_flags(), 0);
            set_mock_flags_word(0xFFFF_F000);
            assert_eq!(control_state_flags(), 0);
            set_mock_flags_word(0xDEAD_B123);
            assert_eq!(control_state_flags(), 0x123);
            set_mock_flags_word(0xFFFF_FFFF);
            assert_eq!(control_state_flags(), 0xFFF);
        }
    }
}
