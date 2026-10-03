//! Tail-record two-variant selector-item constructor — `FUN_0825dfa8` @
//! `0x0825dfa8`. True extent: 212 bytes through `0x0825e07c`: 168 code
//! bytes followed by eleven literal words. The next function begins with
//! `sub r0,r0,#0x1500`. Whole-image A32 decoding verifies two plain inbound
//! BLs at 0x0819fb28 and 0x0819fb40, zero predicated inbound BLs; one plain
//! outbound BL at 0x0825dfd0 to selector_item_base_construct, zero predicated.
//!
//! Zero variant selects item 17 / descriptor 0x8014; any nonzero u32 selects
//! item 18 / descriptor 0x8015. Construct the 0x180-byte base with kind 9,
//! context 55 and the low variant byte as its enable flag. Replace the
//! vtable and populate records 1, 2 and 9..12; only records 1 and 2 replace
//! implementation words. Implementation addresses are opaque stored values,
//! not new call seams. Callers allocate 0x180 bytes and index item byte +0xb4.
//!
//! No deliberate behavioral deviations. Return the base result retained in
//! r0, correcting Ghidra's void signature. Class identity remains unknown;
//! the name describes the observed selector-record layout.

use crate::cxx::selector_item_base::selector_item_base_construct;

/// Construct the tail-record variant and return its object pointer.
///
/// # Safety
/// `this` must address 0x180 writable, four-byte-aligned bytes. The embedded
/// dependency must be configured as for `selector_item_base_construct`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_item_tail_variant_construct(
    this: *mut u32,
    variant: u32,
) -> *mut u32 {
    let (item_id, descriptor) = if variant == 0 { (17, 0x8014) } else { (18, 0x8015) };
    let object = selector_item_base_construct(this, item_id, descriptor, 9, 55, variant as u8);
    object.write(0x089a_3414);
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
    fn full_width_variant_flags_all_records_and_bounds() {
        let _lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        for variant in [0, 1, 2, 0x80, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for old_flags in [0u8, 3, 0x54, 0xff] {
                let mut storage = [0xa5a5_a5a5u32; 0x180 / 4 + 2];
                let object = unsafe { storage.as_mut_ptr().add(1) };
                unsafe {
                    object.cast::<u8>().add(4).write(old_flags);
                    assert_eq!(selector_item_tail_variant_construct(object, variant), object);
                }
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
                let words = &storage[1..storage.len() - 1];
                assert_eq!(words[0], 0x089a_3414);
                assert_eq!(words[1], 0xa5a5_a500 | u32::from((old_flags & !1 | variant as u8) & !2));
                assert_eq!(words[2], 55);
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
                assert_eq!(words[0xb4 / 4], 0xa5a5_a500 | if variant == 0 { 17 } else { 18 });
                assert_eq!(words[0xb8 / 4], if variant == 0 { 0x8014 } else { 0x8015 });
                assert_eq!(words[0xbc / 4], 0xa5a5_a509);
                assert_eq!(words[0xc0 / 4], 0x0898_1630);
                assert_eq!(&words[0x178 / 4..], &[0, 0]);
            }
        }
    }
}
