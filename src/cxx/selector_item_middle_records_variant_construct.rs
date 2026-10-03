//! Middle-record selector-item constructor — `FUN_0826106c` @ `0x0826106c`.
//! True size: 212 bytes (168 code bytes and eleven literal words), ending at
//! `0x08261140`, where the next function begins with `push {r4,lr}`.
//! Whole-image raw A32 decoding finds two plain inbound BLs at 0x0819fa68
//! and 0x0819fa80, zero predicated inbound BLs, and one plain outbound BL
//! at 0x08261094 to selector_item_base_construct; zero predicated outbound BLs.
//!
//! Zero full-width variant selects item 8 / descriptor 0x8007; nonzero
//! selects item 9 / descriptor 0x8008. Construct the 0x180-byte base with
//! kind 9, context 44 and the variant's low byte as its flag. Replace the
//! vtable and install records 1/2 and 5..8; only records 1/2 replace their
//! implementation words. Preserve every other base record.
//!
//! No deliberate behavioral deviations. Return the base result retained
//! in r0, contrary to Ghidra's void declaration; callers index its +0xb4
//! byte. Stored implementation addresses are opaque values, not new seams.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the selector item with middle records populated.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes, with the
/// embedded dependency configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_middle_records_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (8, 0x8007) } else { (9, 0x8008) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 44, variant as u8);
    object.write(0x089a_3758);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x24 / 4).write(0x801e);
    object.cast::<u8>().add(0x28).write(10);
    object.add(0x2c / 4).write(0x08ae_5474);
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
    fn full_width_variant_flags_sparse_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_middle_records_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_3758);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 44);
                // Independent complete record table, including sparse holes.
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (2, 0x801e, 10, 0x08ae_5474),
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
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 8 } else { 9 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8007 } else { 0x8008 });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
