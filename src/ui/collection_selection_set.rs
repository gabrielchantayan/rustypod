//! Collection selection transition — `FUN_0820adac` @ `0x0820adac`.
//! True extent: 192 bytes through `0x0820ae6c`, the next function prologue.
//! Raw-word scan: two plain BL callers (0x0820ae90, 0x0820aed0), zero
//! predicated BL callers; eight plain in-body BLs, zero predicated BLs.
//!
//! Traverse the collection at owner+0xa8 from before-first, clearing bit 3
//! on the element at the current index (+0x110). Clean up and restart, then
//! set bit 3 on the requested element and only then store its index. Missing
//! old/new indices are not clamped; an absent new element leaves the stored
//! index unchanged, even after the old element was deselected. Selecting
//! the same index still performs both transitions.
//!
//! No algorithmic deviations. Calls canonical ports directly; their existing
//! iterator seams retain responsibility for unported collection bookkeeping.
//! Iterator and fetched pointer storage use target-width u32 words on hosts.

use crate::app::vtable_set::{iterator_state_construct, iterator_state_next, iterator_state_cleanup};
use crate::ui::set_flag_bit_3::ui_element_set_flag_bit_3;

/// # Safety
/// `owner` must be word-aligned and contain the live collection at +0xa8 and
/// writable index at +0x110. Fetched u32 pointers must address live UI elements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_collection_selection_set(owner: *mut u8, requested_index: i32) {
    let mut state = [0u32; 5];
    let mut element = 0u32;
    let selected = owner.add(0x110).cast::<i32>();
    iterator_state_construct(state.as_mut_ptr(), owner.add(0xa8), -2);
    let mut index = 0i32;
    while iterator_state_next(state.as_mut_ptr(), (&mut element as *mut u32).cast()) != 0 {
        if selected.read() == index {
            ui_element_set_flag_bit_3(element as *mut u8, 0);
            break;
        }
        index = index.wrapping_add(1);
    }
    iterator_state_cleanup(state.as_mut_ptr());
    iterator_state_construct(state.as_mut_ptr(), owner.add(0xa8), -2);
    index = 0;
    while iterator_state_next(state.as_mut_ptr(), (&mut element as *mut u32).cast()) != 0 {
        if index == requested_index {
            ui_element_set_flag_bit_3(element as *mut u8, 1);
            selected.write(index);
            break;
        }
        index = index.wrapping_add(1);
    }
    iterator_state_cleanup(state.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::vtable_set::{ITERATOR_STATE_REFRESH, ITERATOR_STATE_FETCH};

    unsafe extern "C" fn refresh(state: *mut u32) {
        let position = state.add(2).read() as i32;
        state.add(3).write(if position == -2 { 0 } else { position.wrapping_add(1) as u32 });
    }

    unsafe extern "C" fn fetch(state: *mut u32, out: *mut u8) -> u32 {
        let collection = state.read() as *const u32;
        let index = state.add(2).read() as i32;
        if index < 0 || index >= collection.add(1).read() as i32 {
            return 0;
        }
        out.cast::<u32>().write(collection.add(4 + index as usize).read());
        1
    }

    struct Restore {
        refresh: unsafe extern "C" fn(*mut u32),
        fetch: unsafe extern "C" fn(*mut u32, *mut u8) -> u32,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(ITERATOR_STATE_REFRESH).write(self.refresh);
                core::ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write(self.fetch);
            }
        }
    }

    #[test]
    fn transitions_preserve_unrelated_flags_and_missing_index_state() {
        let _lock = crate::app::vtable_set::tests::SLOT_TEST_LOCK.lock();
        let Some(owner) = crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_COLLECTION_SELECTION_SET, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("ui_collection_selection_set"));
            return;
        };
        unsafe {
            let _restore = Restore {
                refresh: core::ptr::addr_of!(ITERATOR_STATE_REFRESH).read(),
                fetch: core::ptr::addr_of!(ITERATOR_STATE_FETCH).read(),
            };
            core::ptr::addr_of_mut!(ITERATOR_STATE_REFRESH).write(refresh);
            core::ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write(fetch);
            // Empty, first/last, same, absent old, absent new, and negative indices.
            for (count, old, new) in [(0, 0, 0), (3, 0, 2), (3, 2, 0),
                (3, 1, 1), (3, -1, 2), (3, 7, 0), (3, 1, 3), (3, 1, -1)] {
                owner.write_bytes(0, 0x1000);
                let collection = owner.add(0xa8).cast::<u32>();
                collection.add(1).write(count);
                owner.add(0x110).cast::<i32>().write(old);
                for i in 0..3 {
                    let element = owner.add(0x200 + i * 0x100);
                    collection.add(4 + i).write(element as u32);
                    element.add(0xa0).write(1); // Real invalidator's suppression guard.
                    element.add(0x48).cast::<u32>().write(0x800 | if i as i32 == old { 8 } else { 0 });
                }
                ui_collection_selection_set(owner, new);
                let valid_new = new >= 0 && new < count as i32;
                assert_eq!(owner.add(0x110).cast::<i32>().read(), if valid_new { new } else { old });
                for i in 0..3 {
                    let mut expected = 0x800 | if i as i32 == old { 8 } else { 0 };
                    if i < count as usize && i as i32 == old { expected &= !8; }
                    if valid_new && i as i32 == new { expected |= 8; }
                    assert_eq!(owner.add(0x248 + i * 0x100).cast::<u32>().read(), expected,
                        "count={count}, old={old}, new={new}, element={i}");
                }
                assert_eq!(collection.add(3).read(), 0, "observer head remains empty");
            }
        }
    }
}
