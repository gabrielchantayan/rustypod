//! `flagged_pair_construct` — retailOS `FUN_08267b84` at `0x08267b84` (12
//! bytes).
//!
//! Raw `osos.dec` establishes the exact three-instruction extent
//! `0x08267b84..0x08267b8f`: `stm r0,{r1,r3}`, `strb r2,[r0,#8]`, and `bx lr`.
//! The next real function is the independent empty destructor at `0x08267b90`.
//! There are three direct inbound calls, all unconditional plain `bl` at
//! `0x0807a424`, `0x08104238`, and `0x082968e8`; no predicated `bl` calls.
//!
//! Algorithm: initialize the two opaque words of a twelve-byte flagged pair,
//! then store the supplied flag byte. The concrete C++ type is unrecovered, so
//! the existing layout name describes only its observed fields. Deliberate
//! deviations: none.

use crate::cxx::flagged_pair_copy::FlaggedPair;

/// Initializes a flagged pair from two words and an unnormalized flag byte.
///
/// # Safety
///
/// `pair` must be four-byte aligned and writable through +0x08. The retail
/// body has no NULL or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.flagged_pair_construct")]
#[inline(never)]
pub unsafe extern "C" fn flagged_pair_construct(
    pair: *mut FlaggedPair,
    first: u32,
    flag: u8,
    second: u32,
) {
    unsafe {
        core::ptr::addr_of_mut!((*pair).first).write_volatile(first);
        core::ptr::addr_of_mut!((*pair).second).write_volatile(second);
        core::ptr::addr_of_mut!((*pair).flag).write_volatile(flag);
    }
}

#[cfg(test)]
mod tests {
    use super::flagged_pair_construct;
    use crate::cxx::flagged_pair_copy::FlaggedPair;

    #[test]
    fn initializes_words_and_preserves_the_full_flag_byte() {
        let mut pair = FlaggedPair {
            first: 0xa5a5_a5a5,
            second: 0x5a5a_5a5a,
            flag: 0xff,
            reserved: [0x3c; 3],
        };

        unsafe { flagged_pair_construct(&mut pair, 0x0123_4567, 0xfe, 0x89ab_cdef) };

        assert_eq!(pair.first, 0x0123_4567);
        assert_eq!(pair.second, 0x89ab_cdef);
        assert_eq!(pair.flag, 0xfe, "the constructor does not normalize the flag");
        assert_eq!(pair.reserved, [0x3c; 3], "stores stop at byte +0x08");
    }

    #[test]
    fn accepts_zero_values() {
        let mut pair = FlaggedPair {
            first: u32::MAX,
            second: u32::MAX,
            flag: u8::MAX,
            reserved: [0xa5; 3],
        };

        unsafe { flagged_pair_construct(&mut pair, 0, 0, 0) };

        assert_eq!(pair.first, 0);
        assert_eq!(pair.second, 0);
        assert_eq!(pair.flag, 0);
        assert_eq!(pair.reserved, [0xa5; 3]);
    }
}
