//! Append through the collection's shared insertion-and-key-range updater.

use core::ptr;

type InsertAndUpdate = unsafe extern "C" fn(*mut u32, *mut u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_insert_and_update(owner: *mut u32, item: *mut u8, after: u32) {
    let insert: InsertAndUpdate = core::mem::transmute(0x0826_b818usize);
    insert(owner, item, after);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_insert_and_update(_: *mut u32, _: *mut u8, _: u32) {
    panic!("collection_append requires retailOS insertion body 0x0826b818")
}

#[cfg(target_os = "none")]
static mut INSERT_AND_UPDATE: InsertAndUpdate = firmware_insert_and_update;
#[cfg(not(target_os = "none"))]
static mut INSERT_AND_UPDATE: InsertAndUpdate = missing_insert_and_update;

/// `collection_append` — original `FUN_0826b784` at 0x0826b784.
/// True extent: 16 bytes, 0x0826b784..0x0826b794; the next function starts
/// with `push {r4,r5,r6,lr}` at 0x0826b794. Raw words are e5902004,
/// e5922004, e2422001, ea000020. Whole-image aligned ARM branch decoding
/// finds two plain BL callers (0x0812d614, 0x0826bb60), zero predicated BL
/// callers, and no outbound BL: the final B targets 0x0826b818.
///
/// Read the target-width collection pointer at owner+4, read its count at
/// collection+4, and pass count-1 to the shared insertion body. Subtraction
/// wraps: an empty collection passes UINT32_MAX, which that body maps to
/// position zero; otherwise its last-index case maps to INT32_MAX (append).
/// The shared body inserts via virtual slot +0x20 and updates the owner's
/// byte key bounds at +8/+9 from the resulting item. Its identity is based
/// on raw code, not an inferred external callee name.
///
/// Deliberate deviations: the shared body remains retailOS code behind an
/// address-bound volatile seam; LLVM may emit a call/return instead of the
/// original tail branch. No null guards or signed-overflow checks are added.
///
/// # Safety
/// `owner` and its u32 collection pointer must address readable aligned words
/// through +4 and satisfy the shared body's virtual-call and mutation contract.
/// `item` must satisfy that body's contract; it is passed through unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_append(owner: *mut u32, item: *mut u8) {
    let collection = owner.add(1).read() as usize as *const u32;
    let after = collection.add(1).read().wrapping_sub(1);
    ptr::read_volatile(ptr::addr_of!(INSERT_AND_UPDATE))(owner, item, after);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut AFTER: u32 = 0;

    unsafe extern "C" fn capture_index(_: *mut u32, _: *mut u8, after: u32) {
        AFTER = after;
    }

    struct Restore(InsertAndUpdate);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { INSERT_AND_UPDATE = self.0; } }
    }

    #[test]
    fn last_index_wraps_for_empty_and_preserves_full_unsigned_count_range() {
        let _lock = LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::UI_COLLECTION_APPEND, 4096) else { return; };
        unsafe {
            let owner = base.cast::<u32>();
            let collection = owner.add(16);
            owner.write(0xdead_beef);
            owner.add(1).write(collection as usize as u32);
            owner.add(2).write(0x0000_007f);
            collection.write(0xcafe_babe);
            let _restore = Restore(INSERT_AND_UPDATE);
            INSERT_AND_UPDATE = capture_index;
            for (count, expected) in [
                (0, u32::MAX), (1, 0), (2, 1),
                (0x7fff_ffff, 0x7fff_fffe), (0x8000_0000, 0x7fff_ffff),
                (0x8000_0001, 0x8000_0000), (u32::MAX, 0xffff_fffe),
            ] {
                collection.add(1).write(count);
                collection_append(owner, ptr::null_mut());
                assert_eq!(ptr::read(ptr::addr_of!(AFTER)), expected, "count={count:#x}");
                assert_eq!(collection.add(1).read(), count);
                assert_eq!(owner.add(2).read(), 0x0000_007f);
            }
        }
    }
}
