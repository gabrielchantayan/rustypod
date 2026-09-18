//! MOV parser target-word predicate.
//!
//! `mov_parser_slot_14_is_set` — original: `FUN_081c31d0` at load address
//! **0x081c31d0** (**16 bytes**, exactly `0x081c31d0..0x081c31e0`; the next
//! separately linked function starts at `0x081c31e0`). Decoding every aligned
//! ARM B/BL-immediate word in `osos.dec` finds **four inbound plain,
//! unconditional `bl` calls** at `0x081c56a0`, `0x081c5c10`, `0x081c7ea0`,
//! and `0x0827b410`; there are **zero inbound predicated BL calls**.
//!
//! # Algorithm
//!
//! Loads the target-width word at parser offset `+0x14` and returns zero when
//! it is zero, otherwise one. The ARM sequence is `ldr; cmp; movne; bx lr`;
//! no NULL or validity guard precedes the load.
//!
//! # Deliberate deviations
//!
//! None. The slot is represented as `u32`, not a host pointer, so its offset
//! remains the firmware's four-byte target layout on host and device.

/// MOV parser prefix observed by the predicate.
#[repr(C)]
pub struct MovParserSlot14 {
    reserved_00_10: [u32; 5],
    slot_14: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(MovParserSlot14, slot_14)];

/// Reports whether the MOV parser's target word at `+0x14` is set.
///
/// # Safety
///
/// `parser` must be non-NULL, aligned, and readable through offset `+0x14`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_parser_slot_14_is_set(parser: *const MovParserSlot14) -> u32 {
    u32::from(unsafe { (*parser).slot_14 } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_zero_only_for_a_zero_slot() {
        let mut parser = MovParserSlot14 { reserved_00_10: [u32::MAX; 5], slot_14: 0 };
        assert_eq!(unsafe { mov_parser_slot_14_is_set(&parser) }, 0);

        parser.slot_14 = 1;
        assert_eq!(unsafe { mov_parser_slot_14_is_set(&parser) }, 1);
        parser.slot_14 = u32::MAX;
        assert_eq!(unsafe { mov_parser_slot_14_is_set(&parser) }, 1);
    }
}
