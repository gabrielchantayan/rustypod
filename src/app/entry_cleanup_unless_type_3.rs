//! `entry_cleanup_unless_type_3` — retailOS @ `0x0810f92c`.
//!
//! Raw A32 extent: 112 bytes, `[0x0810f92c, 0x0810f99c)`; the next
//! instruction is a separate push. Two inbound plain BLs (0x0810ef98,
//! 0x0810f9c4), zero predicated BLs. Body: three plain BLs to free_wrapper,
//! zero predicated BLs, and one conditional register BLX to vtable slot +4.
//! NULL returns 1; type byte +12 equal to 3 returns 0 without mutation.
//! Otherwise free words +4 and +8 with tag 45, clearing each after release;
//! release a non-NULL object at +16 through its second virtual slot, clear
//! it, free the entry with tag 45, and return 1. Owner is unused.
//!
//! No algorithm deviations. The existing free_wrapper uses heap dispatch;
//! host tests inject releases into the same implementation to observe order.

#[inline(always)]
unsafe fn cleanup_with(entry: *mut u32, mut free: impl FnMut(*mut u8, usize),
    mut release: impl FnMut(u32)) -> u32 {
    if entry.is_null() { return 1; }
    if entry.cast::<u8>().add(12).read() == 3 { return 0; }
    free(entry.add(1).read() as usize as *mut u8, 45);
    entry.add(1).write(0);
    free(entry.add(2).read() as usize as *mut u8, 45);
    entry.add(2).write(0);
    let object = entry.add(4).read();
    if object != 0 { release(object); }
    entry.add(4).write(0);
    free(entry.cast(), 45);
    1
}

/// Release an entry unless its type is 3; NULL is considered removed.
///
/// # Safety
/// A non-NULL `entry` must reference five aligned target words. Its owned
/// pointers must be valid allocator allocations; the +16 object must have
/// a valid target vtable with an `unsafe extern "C" fn(*mut u32)` at +4.
/// Releases must not invalidate the entry before its final free.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_cleanup_unless_type_3(_owner: *mut u32, entry: *mut u32) -> u32 {
    cleanup_with(entry, |ptr, tag| crate::heap::veneers::free_wrapper(ptr, tag), |address| {
        let object = address as usize as *mut u32;
        let vtable = object.read() as usize as *const u32;
        let release: unsafe extern "C" fn(*mut u32) =
            core::mem::transmute(vtable.add(1).read() as usize);
        release(object);
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, vec::Vec};

    #[test]
    fn null_and_retained_entries_do_not_release_or_mutate() {
        unsafe {
            assert_eq!(entry_cleanup_unless_type_3(core::ptr::null_mut(), core::ptr::null_mut()), 1);
            let mut words = [9, 11, 22, 0xaabbcc03, 33];
            let before = words;
            assert_eq!(entry_cleanup_unless_type_3(core::ptr::null_mut(), words.as_mut_ptr()), 0);
            assert_eq!(words, before);
        }
    }

    #[test]
    fn releases_in_order_and_clears_only_after_each_release() {
        for kind in [0, 1, 2, 4, 255] {
            for object in [0, 33] {
                let mut words = [9, 11, 22, 0xaabbcc00 | kind, object];
                let entry = words.as_mut_ptr();
                let events = RefCell::new(Vec::new());
                unsafe {
                    let result = cleanup_with(entry, |ptr, tag| {
                        assert_eq!(tag, 45);
                        events.borrow_mut().push((ptr as usize, [entry.add(1).read(), entry.add(2).read(), entry.add(4).read()]));
                    }, |address| {
                        assert_eq!(address, 33);
                        assert_eq!([entry.add(1).read(), entry.add(2).read(), entry.add(4).read()], [0, 0, 33]);
                        events.borrow_mut().push((33, [0, 0, 33]));
                    });
                    assert_eq!(result, 1);
                }
                let mut expected = std::vec![(11, [11, 22, object]), (22, [0, 22, object])];
                if object != 0 { expected.push((33, [0, 0, 33])); }
                expected.push((entry as usize, [0, 0, 0]));
                assert_eq!(*events.borrow(), expected);
                assert_eq!(words, [9, 0, 0, 0xaabbcc00 | kind, 0]);
            }
        }
    }

    #[test]
    fn null_payloads_still_reach_allocator() {
        let mut words = [7, 0, 0, 0, 0];
        let entry = words.as_mut_ptr();
        let mut freed = Vec::new();
        unsafe {
            assert_eq!(cleanup_with(entry, |ptr, tag| freed.push((ptr as usize, tag)),
                |_| panic!("NULL object released")), 1);
        }
        assert_eq!(freed, [(0, 45), (0, 45), (entry as usize, 45)]);
    }
}
