//! Extended two-variant selector-item constructor — `FUN_0826ac0c` @
//! `0x0826ac0c`. True extent: 232 bytes through `0x0826acf4`, comprising
//! 184 code bytes and twelve literal words; the next function starts with
//! `push {r4-r11,lr}`. Raw whole-image A32 decoding verifies two plain
//! inbound BLs at `0x0819fb88` and `0x0819fba0`, no predicated inbound BLs;
//! one plain outbound BL at `0x0826ac34`, no predicated outbound BLs.
//!
//! Zero variant selects item 21 / descriptor 0x800e; any nonzero u32 selects
//! item 22 / descriptor 0x800f. Construct the 0x180-byte selector-item base
//! with kind 9, context 55, and the variant's low byte as the enable flag.
//! Replace the vtable and populate seven selector records, leaving the
//! unassigned records and five implementation words initialized by the base.
//! Both callers allocate 0x180 bytes and index the returned item at +0xb4.
//!
//! No deliberate behavioral deviations. Return the object retained in r0
//! (Ghidra incorrectly declares void); compare the full-width variant before
//! narrowing the base flag. Implementation literals are opaque stored values,
//! not callable seams. Field names remain structural, as in the base port.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the extended two-variant selector item and return its pointer.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes. The embedded
/// dependency must be configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_extended_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (21, 0x800e) } else { (22, 0x800f) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 55, variant as u8);
    object.write(0x089a_37b0);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x24 / 4).write(0x801e);
    object.cast::<u8>().add(0x28).write(10);
    object.add(0x2c / 4).write(0x08ae_5474);
    object.add(0x3c / 4).write(0x8020);
    object.cast::<u8>().add(0x40).write(12);
    object.add(0x48 / 4).write(0x8021);
    object.cast::<u8>().add(0x4c).write(13);
    object.add(0x54 / 4).write(0x8022);
    object.cast::<u8>().add(0x58).write(14);
    object.add(0x60 / 4).write(0x8023);
    object.cast::<u8>().add(0x64).write(15);
    object.add(0x6c / 4).write(0x8024);
    object.cast::<u8>().add(0x70).write(16);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_variants_flags_records_and_object_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_extended_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_37b0);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 55);
                // Independent expected table, including the base default and
                // all unassigned records and implementation words.
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (2, 0x801e, 10, 0x08ae_5474),
                    (4, 0x8020, 12, 0),
                    (5, 0x8021, 13, 0),
                    (6, 0x8022, 14, 0),
                    (7, 0x8023, 15, 0),
                    (8, 0x8024, 16, 0),
                ] {
                    records[slot * 3] = selector;
                    records[slot * 3 + 1] = tag;
                    records[slot * 3 + 2] = implementation;
                }
                assert_eq!(&words[3..0xb4 / 4], &records);
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 21 } else { 22 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x800e } else { 0x800f });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
