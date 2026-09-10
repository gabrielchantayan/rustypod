//! Image-format descriptor slot update.
//!
//! `image_format_descriptor_slot_set` — original `FUN_081d5f98` @
//! `0x081d5f98` (**60 bytes, `0x081d5f98..0x081d5fd0`**). The next
//! separately linked function begins at `0x081d5fd4`. Decoding every ARM
//! B/BL immediate in `osos.dec` finds **11 direct call sites**, all
//! unconditional plain `bl`; there are no predicated calls or tail branches.
//!
//! # Algorithm
//!
//! The opaque slots object has 36-byte records beginning at word 9. For the
//! selected record, the function stores the current sequence word (word 164)
//! at record word 0, increments that sequence word, then copies the supplied
//! aligned 32-byte image-format descriptor into record words 1 through 8 via
//! the ported IRAM memcpy veneer. It always returns 1. There is no NULL,
//! bounds, or alignment guard. In particular, slot 17 overlaps the sequence
//! word; the copy deliberately follows the increment, preserving that unusual
//! raw-layout behaviour. No deliberate deviations.

use crate::libc::iram_veneers::iram_memcpy_veneer;

const FIRST_SLOT_WORD: u32 = 9;
const SLOT_WORDS: u32 = 9;
const SEQUENCE_WORD: usize = 0xa4;
const DESCRIPTOR_BYTES: usize = 32;

/// Stores one image-format descriptor in an opaque fixed-stride slot object.
///
/// # Safety
///
/// `slots` must point to the retail object's word-addressable storage, and
/// `descriptor` must be word-aligned and readable for 32 bytes. The selected
/// slot and the sequence word must be writable. As in retailOS, this function
/// does not validate any pointer, the slot number, or overlap between the
/// selected record and the sequence word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_slot_set(
    slots: *mut u32,
    slot: u32,
    descriptor: *const u8,
) -> u32 {
    let record = slots.add(slot.wrapping_mul(SLOT_WORDS).wrapping_add(FIRST_SLOT_WORD) as usize);

    record.write(slots.add(SEQUENCE_WORD).read());
    let sequence = slots.add(SEQUENCE_WORD);
    sequence.write(sequence.read().wrapping_add(1));
    iram_memcpy_veneer(record.add(1).cast(), descriptor, DESCRIPTOR_BYTES);

    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const SLOT_ZERO_WORD: usize = FIRST_SLOT_WORD as usize;
    const SLOT_SEVENTEEN_WORD: usize = SLOT_ZERO_WORD + 17 * SLOT_WORDS as usize;

    #[test]
    fn stores_descriptor_and_wraps_sequence() {
        let mut slots = [0xcccc_cccc_u32; SEQUENCE_WORD + 1];
        let descriptor = [
            0x10_u32, 0x2030_4050, 0x6070_8090, 0xa0b0_c0d0,
            0xe0f0_1020, 0x3040_5060, 0x7080_90a0, 0xb0c0_d0e0,
        ];
        slots[SEQUENCE_WORD] = u32::MAX;

        let result = unsafe {
            image_format_descriptor_slot_set(
                slots.as_mut_ptr(),
                0,
                descriptor.as_ptr().cast(),
            )
        };

        assert_eq!(result, 1);
        assert_eq!(slots[SLOT_ZERO_WORD], u32::MAX);
        assert_eq!(&slots[SLOT_ZERO_WORD + 1..SLOT_ZERO_WORD + SLOT_WORDS as usize], &descriptor);
        assert_eq!(slots[SEQUENCE_WORD], 0);
    }

    #[test]
    fn slot_seventeen_copy_overwrites_sequence_after_increment() {
        let mut slots = [0xcccc_cccc_u32; SLOT_SEVENTEEN_WORD + SLOT_WORDS as usize];
        let descriptor = [
            0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444,
            0x5555_5555, 0x6666_6666, 0x7777_7777, 0x8888_8888,
        ];
        slots[SEQUENCE_WORD] = 0xfeed_face;

        unsafe {
            image_format_descriptor_slot_set(
                slots.as_mut_ptr(),
                17,
                descriptor.as_ptr().cast(),
            );
        }

        assert_eq!(slots[SLOT_SEVENTEEN_WORD], 0xfeed_face);
        assert_eq!(
            &slots[SLOT_SEVENTEEN_WORD + 1..SLOT_SEVENTEEN_WORD + SLOT_WORDS as usize],
            &descriptor,
        );
        assert_eq!(slots[SEQUENCE_WORD], descriptor[1]);
    }
}
