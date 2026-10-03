//! Sum products from selected image-format descriptors.
//!
//! Original `FUN_0821af14` @ `0x0821af14`; true extent 96 bytes,
//! `0x0821af14..0x0821af74`, followed by an independent selector function.
//! Raw ARM words verify two outgoing plain BLs and zero predicated BLs:
//! descriptor table getter at 0x081f0258 and vector size at 0x083d76e8.
//! Fetch the context's descriptor table once; return zero if absent. Re-query
//! the selected-index vector size before each iteration, compare unsigned,
//! and accumulate descriptor words +4 times +12 with 32-bit wrapping MLA.
//! Descriptor stride is 36 bytes. Field meanings beyond this product are
//! unproven. No deliberate behavioral deviations; native-pointer repr(C)
//! fields support hosts, with ARM layout asserted. The unported getter stays
//! a retail-address seam, matching image_format_slots_collect_unexcluded.

use crate::cxx::templates::{vector_size_elem4_alias_76e8, VectorBounds};

type SlotsGet = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[repr(C)]
pub struct ImageFormatSelection {
    pub opaque_00: u32,
    pub context: *mut u32,
    pub opaque_08: u32,
    pub selected: VectorBounds,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ImageFormatSelection, context) == 4);
    assert!(core::mem::offset_of!(ImageFormatSelection, selected) == 12);
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get(_: *mut u32) -> *mut u32 {
    panic!("install image-format product sum host getter")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_PRODUCT_SLOTS_GET: SlotsGet = missing_get;

/// # Safety
/// `owner` and its context must be valid and aligned. For a present table,
/// the vector must contain readable u32 indices and each wrapping target
/// address `table + index * 36` must have readable words at +4 and +12.
/// Host callers must install the descriptor-table getter.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_selected_product_sum(owner: *const ImageFormatSelection) -> u32 {
    #[cfg(target_os = "none")]
    let get = core::mem::transmute::<usize, SlotsGet>(0x081f_0258);
    #[cfg(not(target_os = "none"))]
    let get = core::ptr::addr_of!(SELECTED_PRODUCT_SLOTS_GET).read();
    let slots = get((*owner).context);
    if slots.is_null() { return 0; }
    let vector = core::ptr::addr_of!((*owner).selected);
    let mut index = 0u32;
    let mut sum = 0u32;
    while index < vector_size_elem4_alias_76e8(vector) as u32 {
        let selected = ((*vector).begin as *const u32).add(index as usize).read();
        let address = (slots as usize as u32).wrapping_add(selected.wrapping_mul(36));
        let descriptor = address as usize as *const u32;
        sum = sum.wrapping_add(descriptor.add(1).read().wrapping_mul(descriptor.add(3).read()));
        index = index.wrapping_add(1);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn get(context: *mut u32) -> *mut u32 {
        let base = context.add(12).read();
        if base == 0 { core::ptr::null_mut() } else { (base as usize as *mut u32).add(7) }
    }

    #[test]
    fn absent_empty_sparse_duplicate_and_overflow_match_word_reference() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::IMAGE_FORMAT_SELECTED_PRODUCT_SUM, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("image_format_selected_product_sum"));
            return;
        };
        unsafe {
            SELECTED_PRODUCT_SLOTS_GET = get;
            slab.write_bytes(0, 0x1000);
            let context = slab.cast::<u32>();
            let slots = slab.add(0x100).cast::<u32>();
            let mut owner = ImageFormatSelection {
                opaque_00: 0xa5a5_a5a5, context, opaque_08: 0x1234_5678,
                selected: VectorBounds { begin: core::ptr::null_mut(), end: core::ptr::null_mut() },
            };
            // Missing table must not dereference even an unusable vector.
            owner.selected.begin = 1usize as *mut u8;
            owner.selected.end = 9usize as *mut u8;
            assert_eq!(image_format_selected_product_sum(&owner), 0);
            context.add(12).write(slots.sub(7) as usize as u32);
            let indices = [17u32, 0, 4, 17];
            owner.selected.begin = indices.as_ptr() as *mut u8;
            owner.selected.end = owner.selected.begin;
            assert_eq!(image_format_selected_product_sum(&owner), 0);
            let factors = [(0usize, 0xffff_ffffu32, 3u32), (4, 0x8000_0000, 2), (17, 7, 11)];
            for (i, a, b) in factors {
                slots.add(i * 9 + 1).write(a);
                slots.add(i * 9 + 3).write(b);
                slots.add(i * 9 + 2).write(0xdead_beef);
            }
            for count in 1..=indices.len() {
                owner.selected.end = owner.selected.begin.add(count * 4);
                let expected = indices[..count].iter().fold(0u32, |sum, &i| {
                    let (_, a, b) = factors.iter().find(|&&(slot, _, _)| slot == i as usize).unwrap();
                    sum.wrapping_add(a.wrapping_mul(*b))
                });
                assert_eq!(image_format_selected_product_sum(&owner), expected);
            }
            // Target address multiplication wraps, not host usize arithmetic.
            let wrapping_index = [0x4000_0000u32];
            owner.selected.begin = wrapping_index.as_ptr() as *mut u8;
            owner.selected.end = owner.selected.begin.add(4);
            assert_eq!(image_format_selected_product_sum(&owner), 0xffff_fffd);
            assert_eq!((owner.opaque_00, owner.opaque_08), (0xa5a5_a5a5, 0x1234_5678));
        }
    }
}
