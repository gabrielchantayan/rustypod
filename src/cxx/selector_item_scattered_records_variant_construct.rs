//! Scattered-record selector-item constructor — `FUN_08234b08` @ `0x08234b08`.
//! True size: 200 bytes (160 code bytes plus ten literal words), ending at
//! `0x08234bd0`, the next function's push of r4-r11 and lr.
//! Raw A32 decoding finds two plain inbound BLs at 0x0819fb58/0x0819fb70,
//! no predicated inbound BLs, and one plain outbound BL at 0x08234b30 to
//! selector_item_base_construct; no predicated outbound BLs.
//!
//! Zero full-width variant selects item 19 / descriptor 0x8016; nonzero
//! selects item 20 / descriptor 0x8017. Construct the 0x180-byte base with
//! kind 9, context 44 and the variant's low byte as flag. Replace the vtable
//! and populate records 1, 4 and 9..12; only record 1 replaces its implementation.
//! Other records retain base values. Implementation literals are opaque words.
//!
//! No deliberate behavioral deviations. Return the base result retained in
//! r0, correcting Ghidra's void declaration: callers index its +0xb4 byte.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the selector item with scattered records and return its pointer.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes, with the
/// embedded dependency configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_scattered_records_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (19, 0x8016) } else { (20, 0x8017) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 44, variant as u8);
    object.write(0x089a_2354);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x3c / 4).write(0x8020);
    object.cast::<u8>().add(0x40).write(12);
    object.add(0x78 / 4).write(0x8025);
    object.cast::<u8>().add(0x7c).write(17);
    object.add(0x84 / 4).write(0x8026);
    object.cast::<u8>().add(0x88).write(18);
    object.add(0x90 / 4).write(0x8027);
    object.cast::<u8>().add(0x94).write(19);
    object.add(0x9c / 4).write(0x8028);
    object.cast::<u8>().add(0xa0).write(20);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_variant_flags_scattered_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_scattered_records_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_2354);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 44);
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (4, 0x8020, 12, 0),
                    (9, 0x8025, 17, 0),
                    (10, 0x8026, 18, 0),
                    (11, 0x8027, 19, 0),
                    (12, 0x8028, 20, 0),
                ] {
                    records[slot * 3] = selector;
                    records[slot * 3 + 1] = tag;
                    records[slot * 3 + 2] = implementation;
                }
                assert_eq!(&words[3..0xb4 / 4], &records);
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 19 } else { 20 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8016 } else { 0x8017 });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
