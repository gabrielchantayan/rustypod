//! `dynamic_array_move_elements` — `FUN_0808ea6c` @ `0x0808ea6c`.
//! True size: 68 bytes, ending at the next function's push at `0x0808eab0`.
//! Raw A32 branch decoding verifies two inbound BL sites: plain BL at
//! `0x08064720` and BLNE at `0x08058b10`; no inbound tail B. The body has
//! two plain BLs to `indexed_object_element`, no predicated BL, and a tail
//! B to `bcopy` at `0x08042cbc`.
//!
//! Resolve destination at `first + displacement`, then source at `first`,
//! and overlap-safely copy `(last - first + 1) * element_size` bytes. All
//! index/count arithmetic wraps at 32 bits, with no extra range validation.
//! Deliberate deviations: call the established Rust lookup and bcopy ports
//! instead of retail addresses/IRAM dispatch; use IndexedObject's native
//! pointer slot on hosts (the target slot remains at byte offset 24).

use crate::libc::bcopy::bcopy;
use crate::ui::object_state::{indexed_object_element, IndexedObject};

/// Move the inclusive one-based range `first..=last` by `displacement`.
///
/// # Safety
/// `object` must be a readable aligned IndexedObject with a valid storage
/// pointer slot. Both resolved ranges must be valid for the wrapping byte
/// count; invalid indices are not handled by this function in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dynamic_array_move_elements(
    object: *const IndexedObject,
    first: u32,
    last: u32,
    displacement: i32,
) {
    let destination = indexed_object_element(object, first.wrapping_add(displacement as u32));
    let source = indexed_object_element(object, first);
    let bytes = last.wrapping_sub(first).wrapping_add(1)
        .wrapping_mul((*object).element_size);
    bcopy(source, destination, bytes as usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::object_state::INDEXED_OBJECT_TAG;

    #[test]
    fn overlapping_ranges_match_snapshot_in_both_directions() {
        for stride in [1usize, 3, 4, 7] {
            for (first, last, displacement) in [(1u32, 4u32, 1i32), (2, 5, -1), (3, 3, 2), (1, 5, 0)] {
                let mut storage = [0u8; 48];
                for (index, byte) in storage.iter_mut().enumerate() { *byte = index as u8; }
                let mut expected = storage;
                let snapshot = storage;
                let source = (first as usize - 1) * stride;
                let destination = ((first as i32 + displacement) as usize - 1) * stride;
                let bytes = (last - first + 1) as usize * stride;
                expected[destination..destination + bytes]
                    .copy_from_slice(&snapshot[source..source + bytes]);
                let base = storage.as_mut_ptr();
                let object = IndexedObject {
                    type_tag: INDEXED_OBJECT_TAG, element_size: stride as u32,
                    element_count: 6, reserved: [0; 2], storage_ready: 1,
                    storage_pointer_slot: &base,
                };
                unsafe { dynamic_array_move_elements(&object, first, last, displacement); }
                assert_eq!(storage, expected, "stride={stride}, range={first}..={last}, shift={displacement}");
            }
        }
    }

    #[test]
    fn adjacent_reversed_endpoints_produce_zero_byte_copy() {
        let mut storage = [11u8, 22, 33, 44];
        let base = storage.as_mut_ptr();
        let object = IndexedObject {
            type_tag: INDEXED_OBJECT_TAG, element_size: 1, element_count: 4,
            reserved: [0; 2], storage_ready: 1, storage_pointer_slot: &base,
        };
        unsafe { dynamic_array_move_elements(&object, 3, 2, -1); }
        assert_eq!(storage, [11, 22, 33, 44]);
    }
}
