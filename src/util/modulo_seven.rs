//! Modulo seven — `FUN_08079a14` @ 0x08079a14 (20 bytes; 3 inbound plain
//! `bl` call sites, 0 inbound predicated `bl` call sites; 1 outbound plain
//! `bl`, 0 outbound predicated `bl` calls).
//!
//! Algorithm: pass the input and literal seven to retailOS's unsigned divide
//! helper, then move its r1 remainder into r0. Deliberate deviations: Rust
//! calls the existing out-pointer wrapper because its ABI cannot expose the
//! ADS helper's r1 remainder; it does not preserve the ARM callee-save
//! push/pop sequence.

use crate::runtime::rt_div::__rt_udivmod;

/// Returns the unsigned remainder of `value / 7`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn modulo_seven(value: u32) -> u32 {
    let mut remainder = 0;
    __rt_udivmod(value, 7, &mut remainder);
    remainder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_each_remainder_class() {
        for value in 0..=69 {
            assert_eq!(unsafe { modulo_seven(value) }, value % 7, "value {value}");
        }
    }

    #[test]
    fn reduces_large_unsigned_values() {
        for value in [u32::MAX, u32::MAX - 1, 0x8000_0000, 0xffff_fffa] {
            assert_eq!(unsafe { modulo_seven(value) }, value % 7, "value {value:#x}");
        }
    }
}
