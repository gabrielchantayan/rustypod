//! `observable_array_pair_construct` — original: `FUN_081d5f14` @
//! **0x081d5f14**.
//!
//! **36 bytes**, `0x081d5f14..0x081d5f38`: raw ARM calls the ported
//! `observable_array_construct` at `this + 0x08`, then at the first
//! constructor return plus `0x10` (`this + 0x18`). It clears the two leading
//! words through the second constructor's return minus `0x18`, and returns
//! that resulting original `this` pointer. Decoding every ARM B/BL immediate
//! in `osos.dec` finds **6 plain unconditional `bl`** call sites and no
//! predicated calls: 0x0813761c, 0x0820be10, 0x08210810, 0x08210828,
//! 0x08215114, and 0x08223b60. Two direct branches also reach it: `bne`
//! 0x0820bcf8 and tail `b` 0x08210430.
//!
//! # Algorithm
//!
//! Default-construct the two embedded 16-byte observable arrays in ascending
//! address order, then zero only the pair's leading two words. The firmware
//! has no NULL, alignment, or pre-existing-state checks. No deliberate
//! deviations.

use super::observable_array::{observable_array_construct, ObservableArray, OBSERVABLE_ARRAY_SIZE};

/// A 40-byte base subobject with two leading state words and two observable
/// arrays. The leading words have no recovered identity beyond this
/// constructor's unconditional zeroing.
#[repr(C)]
pub struct ObservableArrayPair {
    /// +0x00 and +0x04: words cleared after both subobjects are constructed.
    pub leading_words: [u32; 2],
    /// +0x08: first default-constructed observable array.
    pub first: ObservableArray,
    /// +0x18: second default-constructed observable array.
    pub second: ObservableArray,
}

pub const OBSERVABLE_ARRAY_PAIR_SIZE: usize = 0x28;

const _: [u8; 0x00] = [0; core::mem::offset_of!(ObservableArrayPair, leading_words)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ObservableArrayPair, first)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(ObservableArrayPair, second)];
const _: [u8; OBSERVABLE_ARRAY_PAIR_SIZE] = [0; core::mem::size_of::<ObservableArrayPair>()];
const _: [u8; 0x10] = [0; OBSERVABLE_ARRAY_SIZE];

/// Default-constructs both embedded observable arrays and clears the two
/// leading words.
///
/// Original: `FUN_081d5f14` @ `0x081d5f14` (36 bytes; 6 unconditional `bl`
/// call sites, no predicated calls; binary-scanned).
///
/// # Safety
///
/// `this` must point to at least [`OBSERVABLE_ARRAY_PAIR_SIZE`] writable,
/// word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.observable_array_pair_construct")]
pub unsafe extern "C" fn observable_array_pair_construct(
    this: *mut ObservableArrayPair,
) -> *mut ObservableArrayPair {
    let first = observable_array_construct(core::ptr::addr_of_mut!((*this).first));
    let second = observable_array_construct(first.add(1));
    let pair = second.cast::<u8>().sub(0x18).cast::<ObservableArrayPair>();
    let leading_words = core::ptr::addr_of_mut!((*pair).leading_words).cast::<u32>();

    leading_words.write_volatile(0);
    leading_words.add(1).write_volatile(0);
    pair
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{FrameworkObject, OBSERVABLE_ARRAY_VTABLE};

    fn sentinel_array() -> ObservableArray {
        ObservableArray {
            base: FrameworkObject { vtable: 0xa5a5_a5a5 },
            len: 0xa5a5_a5a5,
            storage: 0xa5a5_a5a5,
            observers: 0xa5a5_a5a5,
        }
    }

    #[test]
    fn constructs_both_arrays_and_returns_pair() {
        let mut pair = ObservableArrayPair {
            leading_words: [0xa5a5_a5a5; 2],
            first: sentinel_array(),
            second: sentinel_array(),
        };

        let returned = unsafe { observable_array_pair_construct(&mut pair) };

        assert!(core::ptr::eq(returned, &mut pair));
        assert_eq!(pair.leading_words, [0, 0]);
        for array in [&pair.first, &pair.second] {
            assert_eq!(array.base.vtable, OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(array.len, 0);
            assert_eq!(array.storage, 0);
            assert_eq!(array.observers, 0);
        }
    }
}
