//! Eight-slot byte identity-table initialization.
//!
//! `initialize_eight_byte_identity_slots` — original: `FUN_08028460` @
//! `0x08028460` (36 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/08028460_FUN_08028460.c`;
//! raw ARM is `0x08028460..0x08028484`.
//!
//! The wrapper invokes the ported byte identity-table initializer at
//! `0x0802b9ec` exactly eight times, once for each consecutive 0x100-byte
//! slot beginning at its argument. Each initialized slot maps byte `n` to `n`.

use super::byte_identity_slot_init::{
    initialize_byte_identity_slot, BYTE_IDENTITY_SLOT_BYTES,
};

/// Number of consecutive slots initialized by the retail wrapper.
pub const BYTE_IDENTITY_SLOT_COUNT: usize = 8;

/// initialize_eight_byte_identity_slots — original: `FUN_08028460` @
/// `0x08028460` (36 bytes).
///
/// Calls the byte identity-table initializer at `base + i * 0x100` for every
/// `i` from zero through seven, in ascending slot order.
/// # Safety
///
/// `base` must designate the first byte of at least eight contiguous
/// 0x100-byte slots, each valid for the retail initializer to write.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_eight_byte_identity_slots(base: *mut u8) {
    for index in 0..BYTE_IDENTITY_SLOT_COUNT {
        initialize_byte_identity_slot(base.add(index * BYTE_IDENTITY_SLOT_BYTES));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_all_eight_slots_in_ascending_256_byte_order() {
        let mut slots = [0xa5u8; BYTE_IDENTITY_SLOT_COUNT * BYTE_IDENTITY_SLOT_BYTES];
        unsafe { initialize_eight_byte_identity_slots(slots.as_mut_ptr()) };

        for (index, &value) in slots.iter().enumerate() {
            assert_eq!(value, (index % BYTE_IDENTITY_SLOT_BYTES) as u8, "byte {index}");
        }
    }
}
