//! Word-vector resize with fill — original: `FUN_083b6b54` at load address
//! `0x083b6b54`.
//!
//! Raw `osos.dec` establishes the exact 124-byte extent: 31 ARM words from
//! `push {r4-r7,lr}` at `0x083b6b54` through `pop {r4-r7,pc}` at
//! `0x083b6bcc`; `0x083b6bd0` starts the next separately linked function.
//! The body has two plain unconditional outbound `bl` calls: tag-3 allocation
//! at `0x082aad74`, then tag-3 deletion at `0x082aad14`; it has no predicated
//! outbound calls. A whole-image raw A32 branch decode finds three inbound
//! calls: predicated `blls` at `0x082a7330` and `0x082a7374`, and plain `bl`
//! at `0x082a74dc`.
//!
//! It allocates `new_len` four-byte elements, copies `min(old_len, new_len)`
//! words from the old allocation, fills the remaining words by repeatedly
//! loading `*fill`, releases the old allocation, then commits the new length
//! and data pointer. Deliberate deviations: the allocation and release calls
//! use the existing Rust tag-3 veneers; target pointers remain `u32` words on
//! host builds.

use crate::heap::veneers::{operator_delete_tag3, operator_new_tag3};

/// Resizes the two-word `{data, length}` vector at `vector`, filling new words.
///
/// # Safety
///
/// `vector` must point to two writable target-width words. Its data word must
/// be null or identify `length` readable words. The tag-3 allocator must
/// return storage for `new_len` words, as retailOS assumes without a null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector4_resize_fill(
    vector: *mut u32,
    new_len: u32,
    fill: *const u32,
) -> *mut u32 {
    let new_data = operator_new_tag3(new_len as usize * core::mem::size_of::<u32>()) as *mut u32;
    let old_data = vector.read() as usize as *mut u32;
    let old_len = vector.add(1).read();
    let copied_len = core::cmp::min(new_len, old_len);

    for index in 0..copied_len as usize {
        new_data.add(index).write(old_data.add(index).read());
    }
    for index in copied_len as usize..new_len as usize {
        new_data.add(index).write(fill.read());
    }

    operator_delete_tag3(old_data.cast());
    vector.add(1).write(new_len);
    vector.write(new_data as usize as u32);
    new_data
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::VECTOR4_RESIZE_FILL, 0x1000).map(|slab| slab as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut u32, *mut u32, *mut u32)> {
        let slab = *FIXTURE;
        slab.map(|base| {
            let vector = base as *mut u32;
            (vector, vector.add(0x20), vector.add(0x80))
        })
    }

    #[test]
    fn grows_copies_words_fills_tail_and_releases_old_data() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((vector, old_data, new_data)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector4_resize_fill");
            return;
        };
        unsafe {
            old_data.write(0x1111_1111);
            old_data.add(1).write(0x2222_2222);
            vector.write(old_data as usize as u32);
            vector.add(1).write(2);
            let fill = 0xa5a5_a5a5;
            set_alloc_ret(new_data.cast());
            assert_eq!(vector4_resize_fill(vector, 5, ptr::addr_of!(fill)), new_data);
            assert_eq!([new_data.read(), new_data.add(1).read(), new_data.add(2).read(), new_data.add(3).read(), new_data.add(4).read()], [0x1111_1111, 0x2222_2222, fill, fill, fill]);
            assert_eq!(vector.read(), new_data as usize as u32);
            assert_eq!(vector.add(1).read(), 5);
        }
        assert_eq!(alloc_log(), (1, 20, 3));
        assert_eq!(free_log(), (1, old_data.cast(), 3));
    }

    #[test]
    fn shrinks_without_reading_fill_and_releases_old_data() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((vector, old_data, new_data)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector4_resize_fill");
            return;
        };
        unsafe {
            old_data.write(7);
            old_data.add(1).write(8);
            old_data.add(2).write(9);
            vector.write(old_data as usize as u32);
            vector.add(1).write(3);
            set_alloc_ret(new_data.cast());
            vector4_resize_fill(vector, 2, ptr::null());
            assert_eq!([new_data.read(), new_data.add(1).read()], [7, 8]);
            assert_eq!(vector.add(1).read(), 2);
        }
        assert_eq!(alloc_log(), (1, 8, 3));
        assert_eq!(free_log(), (1, old_data.cast(), 3));
    }

    #[test]
    fn resizes_empty_vector_to_zero_through_allocator_and_null_delete() {
        let _fixture_lock = FIXTURE_LOCK.lock();
        let _heap = mock_heap();
        let Some((vector, _, new_data)) = (unsafe { fixture() }) else {
            note_missing_u32_fixture("cxx/vector4_resize_fill");
            return;
        };
        unsafe {
            vector.write(0);
            vector.add(1).write(0);
            set_alloc_ret(new_data.cast());
            assert_eq!(vector4_resize_fill(vector, 0, ptr::null()), new_data);
            assert_eq!(vector.read(), new_data as usize as u32);
            assert_eq!(vector.add(1).read(), 0);
        }
        assert_eq!(alloc_log(), (1, 0, 3));
        assert_eq!(free_log().0, 0);
    }
}
