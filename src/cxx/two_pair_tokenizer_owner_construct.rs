//! `two_pair_tokenizer_owner_construct` — `FUN_081e878c` at 0x081e878c.
//! True extent: 48 bytes (44 code bytes and the vtable literal at 0x081e87b8);
//! next function starts at 0x081e87bc. Raw whole-image ARM decoding verifies
//! two inbound plain BLs (0x081361c0, 0x081362ac), zero predicated BLs;
//! the body has two plain BLs and zero predicated BLs.
//!
//! Construct the 20-byte two-pair base, replace its vtable with 0x0898f800,
//! and initialize an empty tokenizer at +20 with the low 16 bits of the
//! delimiter, INT_MAX remaining tokens, and quoting disabled. Return this.
//! Deliberate deviation: inline the verified empty-tokenizer constructor
//! at 0x08161494 (and its two-word zero helper at 0x081bb6b8), following
//! tokenizer.rs precedent. Preserve all padding and ordered base copies.

use super::tokenizer::Tokenizer;
use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;

pub const VTABLE_ADDRESS: u32 = 0x0898_f800;

/// # Safety
/// `this` must be word-aligned and writable for 44 bytes; both pair sources
/// must be word-aligned and readable for eight bytes. Sources may alias this.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_pair_tokenizer_owner_construct(
    this: *mut u8,
    first_pair: *const u8,
    second_pair: *const u8,
    delimiter: u32,
) -> *mut u8 {
    let base = vtable_two_pair_base_construct(this, first_pair, second_pair);
    base.cast::<u32>().write_volatile(VTABLE_ADDRESS);
    let state = base.add(20).cast::<Tokenizer>();
    core::ptr::addr_of_mut!((*state).begin).write_volatile(0);
    core::ptr::addr_of_mut!((*state).end).write_volatile(0);
    core::ptr::addr_of_mut!((*state).delimiter).write_volatile(delimiter as u16);
    core::ptr::addr_of_mut!((*state).cursor).write_volatile(0);
    core::ptr::addr_of_mut!((*state).remaining).write_volatile(i32::MAX);
    core::ptr::addr_of_mut!((*state).allow_quotes).write_volatile(0);
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_dirty_state_without_touching_padding_or_neighbors() {
        for delimiter in [0, 0x3b, 0xffff, 0x1234_5678, u32::MAX] {
            let mut storage = [0xa5a5_a5a5u32; 13];
            let this = unsafe { storage.as_mut_ptr().add(1).cast::<u8>() };
            let first = [0x0123_4567u32, 0x89ab_cdef];
            let second = [0xfedc_ba98u32, 0x7654_3210];
            let returned = unsafe {
                two_pair_tokenizer_owner_construct(
                    this, first.as_ptr().cast(), second.as_ptr().cast(), delimiter,
                )
            };
            assert_eq!(returned, this);
            assert_eq!(storage, [
                0xa5a5_a5a5, VTABLE_ADDRESS, first[0], first[1], second[0], second[1],
                0, 0, 0xa5a5_0000 | (delimiter & 0xffff), 0, 0x7fff_ffff,
                0xa5a5_a500, 0xa5a5_a5a5,
            ]);
        }
    }

    #[test]
    fn aliased_sources_observe_base_stores_before_derived_vtable() {
        let mut storage = [0xcccc_ccccu32; 11];
        let this = storage.as_mut_ptr().cast::<u8>();
        unsafe {
            two_pair_tokenizer_owner_construct(this, this, this.add(4), 0x3b);
        }
        let base_vtable = super::super::vtable_two_pair_base_construct::VTABLE_ADDRESS;
        assert_eq!(&storage[..5], &[VTABLE_ADDRESS, base_vtable, base_vtable, base_vtable, base_vtable]);
        assert_eq!(storage[7], 0xcccc_003b);
        assert_eq!(storage[10], 0xcccc_cc00);
    }
}
