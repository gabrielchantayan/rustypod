//! Cached sorted 'plst' lookup in a 'tdat' element.

use core::ptr;
use super::tdat_class_check::ui_element_is_tdat_class;

/// Identified stock builder at 0x080ce5a8; count-prefixed target-word array.
/// Its comparator remains unresolved; this port does not implement sorting.
pub type SortedPlstArrayCreate = unsafe extern "C" fn(*const u8, u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_sorted_plst_array_create(element: *const u8, mode: u32) -> *mut u32 {
    let create: SortedPlstArrayCreate = core::mem::transmute(0x080c_e5a8usize);
    create(element, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_sorted_plst_array_create(_: *const u8, _: u32) -> *mut u32 {
    panic!("stock sorted plst builder requires a host fixture")
}

/// Dispatch boundary for the identified, unported stock array builder.
pub static mut TDAT_SORTED_PLST_ARRAY_CREATE: SortedPlstArrayCreate = retail_sorted_plst_array_create;

/// `ui_tdat_sorted_plst_at` — FUN_0805269c @ 0x0805269c.
/// True extent [0x0805269c,0x08052728): 140 bytes, next word is a push.
/// Whole-image aligned ARM decoding: two inbound plain BLs (0x08068ab4,
/// 0x080ca7c4), zero predicated; three outbound plain BLs, zero predicated
/// (class check at 0x080526a8; builder at 0x080526e0 and 0x08052704).
/// Reject NULL/non-'tdat' and unsigned index >= element's +0x30 count.
/// Zero mode selects +0x910; any nonzero mode selects +0x914. Lazily create
/// the selected cache with normalized mode 0/1, store even a NULL result,
/// and return array[index+1] or zero. The array's own count is not checked.
/// Deliberate deviations: reuse the Rust class predicate, merge the two
/// cache branches, and invoke the stock builder through an explicit seam.
/// No comparator identity or alternative sorting algorithm is assumed.
///
/// # Safety
/// Non-NULL element must have an aligned readable class word at +4.
/// Accepted elements require readable +0x30 and writable +0x910/+0x914.
/// Nonzero cache words must address aligned target-word arrays readable at
/// index+1. Builder must satisfy that contract and return a u32-fit pointer.
/// Caller must serialize cache access and dispatch-seam replacement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_tdat_sorted_plst_at(element: *mut u8, index: u32, mode: u32) -> u32 {
    if ui_element_is_tdat_class(element) == 0 {
        return 0;
    }
    if index >= element.add(0x30).cast::<u32>().read() {
        return 0;
    }
    let mode = (mode != 0) as u32;
    let cache = element.add(0x910 + mode as usize * 4).cast::<u32>();
    if cache.read() == 0 {
        let create = ptr::read_volatile(ptr::addr_of!(TDAT_SORTED_PLST_ARRAY_CREATE));
        cache.write(create(element, mode) as usize as u32);
    }
    let array = cache.read();
    if array == 0 { return 0; }
    let offset = index.wrapping_mul(4).wrapping_add(4);
    (array as usize as *const u8).wrapping_add(offset as usize).cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut ARRAYS: [*mut u32; 2] = [ptr::null_mut(); 2];
    static mut CALLS: [u32; 2] = [0; 2];
    unsafe extern "C" fn create(_: *const u8, mode: u32) -> *mut u32 {
        CALLS[mode as usize] += 1;
        ARRAYS[mode as usize]
    }
    struct Restore(SortedPlstArrayCreate);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { TDAT_SORTED_PLST_ARRAY_CREATE = self.0; } }
    }

    #[test]
    fn rejects_invalid_inputs_and_preserves_independent_lazy_caches() {
        let _lock = LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TDAT_SORTED_PLST_AT, 0x2000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("tdat_sorted_plst_at"));
            return;
        };
        unsafe {
            let _restore = Restore(TDAT_SORTED_PLST_ARRAY_CREATE);
            TDAT_SORTED_PLST_ARRAY_CREATE = create;
            CALLS = [0; 2];
            slab.write_bytes(0, 0x2000);
            let first = slab.add(0x1000).cast::<u32>();
            let second = slab.add(0x1100).cast::<u32>();
            // Deliberately disagree with the element count: accessor skips header.
            first.write(0);
            first.add(1).write(0x12345678);
            first.add(2).write(0xfedcba98);
            second.write(99);
            second.add(1).write(0x87654321);
            second.add(2).write(0);
            ARRAYS = [first, ptr::null_mut()];
            assert_eq!(ui_tdat_sorted_plst_at(ptr::null_mut(), 0, 0), 0);
            slab.add(0x30).cast::<u32>().write(2);
            assert_eq!(ui_tdat_sorted_plst_at(slab, 0, 0), 0);
            slab.add(4).cast::<u32>().write(0x74646174);
            for index in [2, u32::MAX] {
                assert_eq!(ui_tdat_sorted_plst_at(slab, index, 0), 0);
            }
            slab.add(0x30).cast::<u32>().write(0);
            assert_eq!(ui_tdat_sorted_plst_at(slab, 0, 1), 0);
            assert_eq!(CALLS, [0, 0]);
            slab.add(0x30).cast::<u32>().write(2);
            assert_eq!(ui_tdat_sorted_plst_at(slab, 1, 0), 0xfedcba98);
            ARRAYS[0] = ptr::null_mut();
            assert_eq!(ui_tdat_sorted_plst_at(slab, 0, 0), 0x12345678);
            assert_eq!(ui_tdat_sorted_plst_at(slab, 0, 7), 0);
            assert_eq!(slab.add(0x914).cast::<u32>().read(), 0);
            ARRAYS[1] = second;
            assert_eq!(ui_tdat_sorted_plst_at(slab, 0, u32::MAX), 0x87654321);
            assert_eq!(ui_tdat_sorted_plst_at(slab, 1, 1), 0);
            assert_eq!(CALLS, [1, 2]);
            assert_eq!(slab.add(0x910).cast::<u32>().read(), first as usize as u32);
            assert_eq!(slab.add(0x914).cast::<u32>().read(), second as usize as u32);
        }
    }
}
