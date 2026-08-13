//! Address-distinct eight-slot byte identity-table initialization alias.
//!
//! `initialize_eight_byte_identity_slots_alias` — original: `FUN_08028490` @
//! `0x08028490` (36 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/08028490_FUN_08028490.c`;
//! raw ARM is `0x08028490..0x080284b4`.
//!
//! This separately hookable, byte-identical alias of
//! [`super::eight_slot_identity_init::initialize_eight_byte_identity_slots`]
//! calls [`super::byte_identity_slot_init::initialize_byte_identity_slot`]
//! once for each of eight adjacent 0x100-byte slots. Each call produces the
//! byte identity mapping `slot[n] = n`.

use super::byte_identity_slot_init::{
    initialize_byte_identity_slot, BYTE_IDENTITY_SLOT_BYTES,
};

/// Number of consecutive slots initialized by the retail wrapper.
const BYTE_IDENTITY_SLOT_COUNT: usize = 8;

/// initialize_eight_byte_identity_slots_alias — original: `FUN_08028490` @
/// `0x08028490` (36 bytes).
///
/// Address-distinct alias of
/// [`super::eight_slot_identity_init::initialize_eight_byte_identity_slots`]
/// at `0x08028460`. Initializes each slot at `base + slot_index * 0x100` in
/// ascending order for `slot_index` in `0..8`, by directly calling the recovered
/// retail helper at `0x0802b9ec`.
///
/// # Safety
///
/// `base` must designate the first byte of at least eight contiguous
/// 0x100-byte writable slots.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    unsafe(link_section = ".text.initialize_eight_byte_identity_slots_alias")
)]
#[inline(never)]
pub unsafe extern "C" fn initialize_eight_byte_identity_slots_alias(base: *mut u8) {
    for slot_index in 0..BYTE_IDENTITY_SLOT_COUNT {
        initialize_byte_identity_slot(base.add(slot_index * BYTE_IDENTITY_SLOT_BYTES));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn alias_initializes_eight_adjacent_byte_identity_slots() {
        let mut slots = [0xa5u8; BYTE_IDENTITY_SLOT_COUNT * BYTE_IDENTITY_SLOT_BYTES + 2];
        let base = unsafe { slots.as_mut_ptr().add(1) };

        unsafe { initialize_eight_byte_identity_slots_alias(base) };

        assert_eq!(slots[0], 0xa5, "byte before slots");
        assert_eq!(slots[slots.len() - 1], 0xa5, "byte after slots");
        for (index, &value) in slots[1..slots.len() - 1].iter().enumerate() {
            assert_eq!(value, (index % BYTE_IDENTITY_SLOT_BYTES) as u8, "entry {index}");
        }
    }
}
