//! Tests whether an opaque object's kind byte is one of the three supported values.
//!
//! `object_kind_is_two_five_or_seven` — original: `FUN_081325b4` @
//! `0x081325b4` (28 bytes, `0x081325b4..0x081325cc`). Raw ARM words establish
//! that `ldr r0, [r0, #0x80]` at `0x081325d0` starts the next real function.
//! The leaf has zero outgoing plain BL instructions and zero predicated BL
//! instructions; a full-image aligned A32 decode finds three inbound plain BL
//! sites and zero predicated inbound BL forms. It loads byte `+0x1a` and
//! returns one when its kind is 2, 5, or 7; otherwise it returns zero.
//!
//! Sources: `ipod-decomp/work/firmware/osos.dec`,
//! `ipod-decomp/decomp/osos.asm`, and the three direct callers
//! `FUN_081323ac`, `FUN_08132760`, and `FUN_08132d9c`.
//!
//! Deliberate deviations: Rust uses a valid host pointer in tests rather than
//! a firmware-address object.

/// Returns one when byte `+0x1a` is kind 2, 5, or 7.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes byte `+0x1a`.
/// The pointer may be unaligned because retailOS performs a byte load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_kind_is_two_five_or_seven(object: *const u8) -> u32 {
    let kind = object.add(0x1a).read();
    if kind == 7 || kind == 5 || kind == 2 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIND: usize = 0x1a;
    const GUARD: u8 = 0xa5;

    #[test]
    fn accepts_exactly_the_three_supported_kinds() {
        let mut object = [GUARD; KIND + 2];

        for (kind, expected) in [(0u8, 0), (1, 0), (2, 1), (3, 0), (5, 1), (6, 0), (7, 1), (8, 0), (u8::MAX, 0)] {
            object[KIND] = kind;
            assert_eq!(unsafe { object_kind_is_two_five_or_seven(object.as_ptr()) }, expected, "kind={kind:#04x}");
        }
    }

    #[test]
    fn reads_only_the_kind_byte_without_mutation() {
        let mut object = [GUARD; KIND + 2];
        object[KIND - 1] = 0x3c;
        object[KIND] = 5;
        object[KIND + 1] = 0xc3;
        let before = object;

        assert_eq!(unsafe { object_kind_is_two_five_or_seven(object.as_ptr()) }, 1);
        assert_eq!(object, before, "a predicate must not mutate its object");
    }
}
