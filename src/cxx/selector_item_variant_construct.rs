//! Two-variant selector-item constructor — `FUN_0826b05c` @ `0x0826b05c`.
//! True extent: 192 bytes through `0x0826b11c` (152 code bytes followed by
//! ten literal words); the next function starts with `push {r3-r9,lr}`.
//! Whole-image A32 decoding verifies two plain inbound BLs at `0x0819fbb8`
//! and `0x0819fbd0`, no predicated BLs; one plain outbound BL, no predicated
//! BLs, to the ported selector-item base constructor at `0x08218b10`.
//!
//! A zero variant selects item 23 / descriptor 0x8010; every nonzero u32
//! selects item 24 / descriptor 0x8011. Construct the 0x180-byte base with
//! kind 9, context 55 and the variant's low byte as its enable flag, then
//! replace its vtable and install five selector records. Only the first
//! two records replace implementation words; the remaining ones retain
//! the base's zero implementation. Both callers allocate 0x180 bytes and
//! index the returned object's item byte at +0xb4.
//!
//! No deliberate behavioral deviations. Preserve the full-width variant
//! comparison separately from the base's byte flag, and return the base
//! result retained in r0 (Ghidra incorrectly declares a void return).
//! Literal implementation addresses are opaque stored values, not new seams.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the two-variant selector item and return its object pointer.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes. The embedded
/// base dependency must be configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (23, 0x8010) } else { (24, 0x8011) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 55, variant as u8);
    object.write(0x089a_37c8);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x24 / 4).write(0x801e);
    object.cast::<u8>().add(0x28).write(10);
    object.add(0x2c / 4).write(0x08ae_5474);
    object.add(0x3c / 4).write(0x8020);
    object.cast::<u8>().add(0x40).write(12);
    object.add(0x78 / 4).write(0x8025);
    object.cast::<u8>().add(0x7c).write(17);
    object.add(0x84 / 4).write(0x8026);
    object.cast::<u8>().add(0x88).write(18);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_width_flags_selector_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        // Exercise zero, both caller variants, noncanonical flag bits, and
        // nonzero values whose low byte is zero. No new dependency seam.
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_37c8);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 55);
                // Independent expected table: all fourteen 12-byte records,
                // including unpopulated slots and preserved default record.
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (2, 0x801e, 10, 0x08ae_5474),
                    (4, 0x8020, 12, 0),
                    (9, 0x8025, 17, 0),
                    (10, 0x8026, 18, 0),
                ] {
                    records[slot * 3] = selector;
                    records[slot * 3 + 1] = tag;
                    records[slot * 3 + 2] = implementation;
                }
                assert_eq!(&words[3..0xb4 / 4], &records);
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 23 } else { 24 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8010 } else { 0x8011 });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
