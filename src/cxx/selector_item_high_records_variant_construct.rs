//! High-record two-variant selector-item constructor — `FUN_08261548` @
//! `0x08261548`. True extent: 212 bytes through `0x0826161c`: 168 code
//! bytes and eleven literal words, followed by a byte-swap function's
//! `lsl r2, r1, #8`. Raw whole-image A32 decoding finds two plain inbound
//! BLs at 0x0819fa98 and 0x0819fab0, zero predicated inbound BLs; one
//! plain outbound BL at 0x08261570, zero predicated outbound BLs.
//!
//! Zero variant selects item 10 / descriptor 0x8009; any nonzero u32
//! selects item 11 / descriptor 0x800a. Construct the 0x180-byte base with
//! kind 9, context 44, and the low variant byte as the enable flag. Replace
//! its vtable, set records 1, 2 and 9..12, and retain the base defaults
//! in every other record. Implementation addresses are opaque stored
//! words, not callable seams. Both callers allocate 0x180 bytes and index
//! the returned object's item byte at +0xb4.
//!
//! No deliberate behavioral deviations. Preserve the pointer retained in
//! r0 (Ghidra incorrectly declares void), and compare the full-width variant
//! before narrowing the flag. Names are structural, as in the base port.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the high-record selector variant and return its object pointer.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes. The embedded
/// dependency must be configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_high_records_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (10, 0x8009) } else { (11, 0x800a) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 44, variant as u8);
    object.write(0x089a_3770);
    object.add(0x18 / 4).write(0x801d);
    object.cast::<u8>().add(0x1c).write(9);
    object.add(0x20 / 4).write(0x08ae_5444);
    object.add(0x24 / 4).write(0x801e);
    object.cast::<u8>().add(0x28).write(10);
    object.add(0x2c / 4).write(0x08ae_5474);
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
    fn full_width_selection_flags_sparse_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_high_records_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_3770);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 44);
                // Independent record table checks holes and implementation words,
                // not only the fields explicitly written by the derived constructor.
                let mut records = [0u32; 0xa8 / 4];
                for (slot, selector, tag, implementation) in [
                    (0, 0x801c, 8, 0x08ae_5444),
                    (1, 0x801d, 9, 0x08ae_5444),
                    (2, 0x801e, 10, 0x08ae_5474),
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
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 10 } else { 11 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8009 } else { 0x800a });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
