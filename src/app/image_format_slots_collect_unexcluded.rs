//! Collect populated image-format slot indices not in an owner's exclusion vector.
//!
//! Original `FUN_0821b220` @ `0x0821b220`, 108 bytes, ending with the
//! return at 0x0821b288; the next function starts at 0x0821b28c.
//! Raw A32 decoding verifies two inbound plain BLs (0x0821b088, 0x0821b788)
//! and five outbound plain BLs, with no predicated BLs in either direction.
//! Fetch the descriptor slots from the owner's context, reset their shared
//! cursor, and advance once per populated descriptor. Append each index whose
//! exclusion query returns zero, preserving iteration order. Re-read the count
//! on every iteration; leave the shared cursor at the last visited slot.
//! No deliberate behavioral deviations. The slots getter is a shared Rust port;
//! remaining unported callees use retail-address seams and host equivalents.
//! No capacity or NULL checks.

use super::image_format_descriptor_slot_count::image_format_descriptor_slot_count;
use super::image_format_context_slots_get::image_format_context_slots_get;

type CursorReset = unsafe extern "C" fn(*mut u32);
type CursorNext = unsafe extern "C" fn(*mut u32) -> u32;
type IsExcluded = unsafe extern "C" fn(*mut u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
pub struct CollectionOps {
    pub cursor_reset: CursorReset,
    pub cursor_next: CursorNext,
    pub is_excluded: IsExcluded,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reset(_: *mut u32) { panic!("install slot collection host seams") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_next(_: *mut u32) -> u32 { panic!("install slot collection host seams") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_excluded(_: *mut u32, _: u32) -> u32 { panic!("install slot collection host seams") }
#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_OPS: CollectionOps = CollectionOps {
    cursor_reset: missing_reset,
    cursor_next: missing_next, is_excluded: missing_excluded,
};

/// # Safety
/// `owner` contains a valid target-width context pointer at +4 and an exclusion
/// vector at +0xc. Its context yields writable descriptor slots through +0x290.
/// `output` has room for every unexcluded index; it need not be valid when none
/// are emitted. All pointers are aligned. Host seams must be installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_slots_collect_unexcluded(owner: *mut u32, output: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    let (reset, next, excluded) = (
        core::mem::transmute::<usize, CursorReset>(0x081d_5fd4),
        core::mem::transmute::<usize, CursorNext>(0x081d_5f54),
        core::mem::transmute::<usize, IsExcluded>(0x0821_ae60),
    );
    #[cfg(not(target_os = "none"))]
    let (reset, next, excluded) = (
        core::ptr::addr_of!(COLLECTION_OPS.cursor_reset).read(),
        core::ptr::addr_of!(COLLECTION_OPS.cursor_next).read(),
        core::ptr::addr_of!(COLLECTION_OPS.is_excluded).read(),
    );
    let context = owner.add(1).read() as usize as *const u32;
    let slots = image_format_context_slots_get(context) as usize as *mut u32;
    reset(slots);
    let mut visited = 0u32;
    let mut written = 0u32;
    while image_format_descriptor_slot_count(slots) > visited {
        let index = next(slots);
        let omit = excluded(owner, index);
        visited = visited.wrapping_add(1);
        if omit == 0 {
            output.add(written as usize).write(index);
            written = written.wrapping_add(1);
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    // Behavioral equivalents of the three remaining retail callees, not exports.
    unsafe extern "C" fn reset(slots: *mut u32) { slots.add(163).write(u32::MAX); }
    unsafe extern "C" fn next(slots: *mut u32) -> u32 {
        let mut index = slots.add(163).read();
        loop {
            index = index.wrapping_add(1);
            if index > 17 { index = u32::MAX; break; }
            if slots.add(index as usize * 9 + 9).read() != u32::MAX { break; }
        }
        slots.add(163).write(index);
        index
    }
    unsafe extern "C" fn excluded(owner: *mut u32, index: u32) -> u32 {
        let start = owner.add(3).read();
        let end = owner.add(4).read();
        let count = ((end.wrapping_sub(start) as i32) >> 2) as u32;
        for i in 0..count {
            if (start as usize as *const u32).add(i as usize).read() == index { return 1; }
        }
        0
    }

    #[test]
    fn empty_sparse_and_full_exclusion_preserve_cursor_and_output_bounds() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::IMAGE_FORMAT_SLOTS_COLLECT_UNEXCLUDED, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("image_format_slots_collect_unexcluded"));
            return;
        };
        unsafe {
            COLLECTION_OPS = CollectionOps { cursor_reset: reset, cursor_next: next, is_excluded: excluded };
            slab.write_bytes(0, 0x1000);
            let owner = slab.cast::<u32>();
            let context = slab.add(0x100).cast::<u32>();
            let slots = slab.add(0x200).cast::<u32>();
            let exclusions = slab.add(0x600).cast::<u32>();
            owner.add(1).write(context as usize as u32);
            context.add(12).write(slots.sub(7) as usize as u32);
            owner.add(3).write(exclusions as usize as u32);
            owner.add(4).write(exclusions as usize as u32);
            slots.add(163).write(7);
            assert_eq!(image_format_slots_collect_unexcluded(owner, core::ptr::null_mut()), 0);
            assert_eq!(slots.add(163).read(), u32::MAX);
            for i in 0..18 { slots.add(i * 9 + 9).write(u32::MAX); }
            for i in [0usize, 4, 17] { slots.add(i * 9 + 9).write(123); }
            slots.add(164).write(3);
            exclusions.write(4);
            exclusions.add(1).write(4); // Duplicate exclusions must not duplicate output.
            owner.add(4).write(exclusions.add(2) as usize as u32);
            let mut output = [0xfeed_face; 5];
            assert_eq!(image_format_slots_collect_unexcluded(owner, output.as_mut_ptr().add(1)), 2);
            assert_eq!(output, [0xfeed_face, 0, 17, 0xfeed_face, 0xfeed_face]);
            assert_eq!(slots.add(163).read(), 17);
            exclusions.write(0);
            exclusions.add(1).write(4);
            exclusions.add(2).write(17);
            owner.add(4).write(exclusions.add(3) as usize as u32);
            assert_eq!(image_format_slots_collect_unexcluded(owner, core::ptr::null_mut()), 0);
            assert_eq!(slots.add(163).read(), 17);
            owner.add(4).write(exclusions as usize as u32);
            assert_eq!(image_format_slots_collect_unexcluded(owner, output.as_mut_ptr().add(1)), 3);
            assert_eq!(output, [0xfeed_face, 0, 4, 17, 0xfeed_face]);
        }
    }
}
