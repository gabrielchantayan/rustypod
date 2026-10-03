//! Split-record selector-item constructor — `FUN_08234f2c` @ `0x08234f2c`.
//! True size: 172 bytes (136 code bytes plus nine literal words), ending at
//! `0x08234fd8`, the next function's `push {r4,lr}`.
//! Raw A32 decoding finds two plain inbound BLs at 0x0819fa38/0x0819fa50,
//! no predicated inbound BLs, and one plain outbound BL at 0x08234f54 to
//! selector_item_base_construct; no predicated outbound BLs.
//!
//! Zero full-width variant selects item 6 / descriptor 0x8005; any nonzero
//! variant selects item 7 / descriptor 0x8006. Construct the 0x180-byte base
//! with kind 9, context 44 and the variant's low byte as its flag. Replace
//! the vtable and install records 1/2 and 11/12, replacing implementation
//! words only in records 1/2. All other records retain base values.
//!
//! No deliberate behavioral deviations. Return the base result retained
//! in r0, unlike Ghidra's void declaration: callers index its +0xb4 byte.
//! Implementation-address literals are opaque values, not dispatch seams.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the selector item with two separated record pairs.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes, with the
/// embedded dependency configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_split_records_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (6, 0x8005) } else { (7, 0x8006) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 44, variant as u8);
    object.write(0x089a_236c);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x24 / 4).write(0x801e);
    object.cast::<u8>().add(0x28).write(10);
    object.add(0x2c / 4).write(0x08ae_5474);
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
    fn full_width_variant_flags_split_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap();
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_split_records_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_236c);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 44);
                // Independent complete record table: sparse holes must remain zero.
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (2, 0x801e, 10, 0x08ae_5474),
                    (11, 0x8027, 19, 0),
                    (12, 0x8028, 20, 0),
                ] {
                    records[slot * 3] = selector;
                    records[slot * 3 + 1] = tag;
                    records[slot * 3 + 2] = implementation;
                }
                assert_eq!(&words[3..0xb4 / 4], &records);
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 6 } else { 7 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8005 } else { 0x8006 });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
