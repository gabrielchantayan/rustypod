//! Constructor @ **0x0820be04**, original `FUN_0820be04`.
//!
//! True extent: **60 bytes** through 0x0820be40 (52 code bytes and
//! literals 0x0899227c / 0x089a6044 at 0x0820be38 / 0x0820be3c).
//! Whole-image A32 decoding finds two inbound plain BLs (0x0820bd5c,
//! 0x0820bdd4), zero predicated BLs; the body has two plain BLs and zero
//! predicated BLs. Both callers allocate 0x48 bytes before construction.
//!
//! Install the owner vtable, construct the observable-array pair at +0x18,
//! recover the owner from the returned pair, install the trailing vtable
//! at +0x40, clear +0x44, then clear +8, +12, +20, +16 in that order.
//! Word +4 is deliberately untouched. The object's application role and
//! the four cleared state words remain unidentified.
//!
//! Deliberate deviation: the four-store helper at 0x0820bdec is inlined;
//! its raw body has no other effects and preserves r2 (the return base).

use super::observable_array_pair::{observable_array_pair_construct, ObservableArrayPair};

pub const OBSERVABLE_ARRAY_PAIR_OWNER_VTABLE: u32 = 0x0899_227c;
pub const OBSERVABLE_ARRAY_PAIR_OWNER_TRAILING_VTABLE: u32 = 0x089a_6044;

/// Target-width fields retain the firmware's layout on hosts as well.
#[repr(C)]
pub struct ObservableArrayPairOwner {
    pub vtable: u32,
    pub preserved_word: u32,
    pub state_words: [u32; 4],
    pub pair: ObservableArrayPair,
    pub trailing_vtable: u32,
    pub trailing_state: u32,
}

const _: [u8; 0x18] = [0; core::mem::offset_of!(ObservableArrayPairOwner, pair)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(ObservableArrayPairOwner, trailing_vtable)];
const _: [u8; 0x48] = [0; core::mem::size_of::<ObservableArrayPairOwner>()];

/// Original: 0x0820be04 (60 bytes; two inbound unconditional BLs).
///
/// # Safety
/// `owner` must address 0x48 writable, word-aligned bytes. Construction
/// does not release pre-existing owned storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_pair_owner_construct(
    owner: *mut ObservableArrayPairOwner,
) -> *mut ObservableArrayPairOwner {
    core::ptr::addr_of_mut!((*owner).vtable).write_volatile(OBSERVABLE_ARRAY_PAIR_OWNER_VTABLE);
    let pair = observable_array_pair_construct(core::ptr::addr_of_mut!((*owner).pair));
    let result = pair.cast::<u8>().sub(0x18).cast::<ObservableArrayPairOwner>();
    core::ptr::addr_of_mut!((*result).trailing_vtable).write_volatile(OBSERVABLE_ARRAY_PAIR_OWNER_TRAILING_VTABLE);
    core::ptr::addr_of_mut!((*result).trailing_state).write_volatile(0);
    let state = core::ptr::addr_of_mut!((*result).state_words).cast::<u32>();
    state.write_volatile(0);
    state.add(1).write_volatile(0);
    state.add(3).write_volatile(0);
    state.add(2).write_volatile(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE;

    #[test]
    fn dirty_storage_preserves_reserved_word_and_guards() {
        for fill in [0, u32::MAX, 0xa5a5_5a5a] {
            let mut words = [fill; 20];
            words[2] = 0x1234_5678;
            let owner = unsafe { words.as_mut_ptr().add(1).cast::<ObservableArrayPairOwner>() };
            let returned = unsafe { observable_array_pair_owner_construct(owner) };
            assert_eq!(returned, owner);
            let mut expected = [0; 20];
            expected[0] = fill;
            expected[19] = fill;
            expected[1] = OBSERVABLE_ARRAY_PAIR_OWNER_VTABLE;
            expected[2] = 0x1234_5678;
            expected[9] = OBSERVABLE_ARRAY_VTABLE;
            expected[13] = OBSERVABLE_ARRAY_VTABLE;
            expected[17] = OBSERVABLE_ARRAY_PAIR_OWNER_TRAILING_VTABLE;
            assert_eq!(words, expected);
            unsafe { observable_array_pair_owner_construct(owner); }
            assert_eq!(words, expected);
        }
    }
}
