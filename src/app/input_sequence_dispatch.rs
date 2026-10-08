//! Input-sequence event dispatcher — FUN_08129c04 @ 0x08129c04.
//!
//! Raw extent [0x08129c04, 0x08129f60): 860 bytes, including the branch
//! table. The next function starts with its own push at 0x08129f60.
//! Contains 17 plain BLs, three predicated BLs, six plain BLX-register
//! instructions and one predicated BLX-register instruction. Two inbound
//! plain BLs occur at 0x0812961c and 0x08129a40; no predicated inbound BLs.
//!
//! Dispatch events 0x20..0x2f: select/clear actions, enter sliding-window
//! modes, erase primary item bounds, advance the window, clear a collection,
//! or commit alternate items. Returns zero for unsupported events, one for
//! handled events (including recognized no-ops). Arithmetic is ARM-width.
//!
//! Deliberate deviations: shared mode-transition code replaces three copies;
//! the empty draw-state destructor is omitted. Collection vtables use native
//! pointer widths on hosts; owner fields retain target-width u32 offsets.
//! Unported clear/reacquire, reposition, and commit helpers retain verified
//! direct-address target seams; host execution panics if those are reached.

use crate::app::input_sequence_find_item::input_sequence_find_item;
use crate::app::input_sequence_item_acquire::input_sequence_item_acquire;
use crate::app::input_sequence_item_clear_action::input_sequence_item_clear_action;
use crate::cursor::{cursor_init, cursor_advance, cursor_invalidate, Collection, Cursor};
use crate::cxx::draw_state::draw_state_construct;
use crate::cxx::draw_state_color::draw_state_set_foreground_color;
use crate::cxx::draw_state_fill::draw_state_fill_rect_foreground;
use crate::ui::content_bounds::ui_offset_bounds;
use crate::ui::draw_state_setup::draw_state_configure_for_element;
use crate::ui::rect::Rect;

#[repr(C)]
struct CollectionPrefix {
    vtable: *const usize,
    count: i32,
}

#[inline(always)]
unsafe fn word(state: *mut u8, offset: usize) -> *mut u32 {
    state.add(offset).cast()
}

#[inline(always)]
unsafe fn collection(state: *mut u8, offset: usize) -> *mut CollectionPrefix {
    word(state, offset).read() as usize as *mut CollectionPrefix
}

#[inline(always)]
unsafe fn clear_collection(value: *mut CollectionPrefix) {
    let clear: unsafe extern "C" fn(*mut CollectionPrefix) =
        core::mem::transmute((*value).vtable.add(12).read());
    clear(value);
}

#[inline(always)]
unsafe fn remove_item(value: *mut CollectionPrefix, item: *mut u8) {
    let remove: unsafe extern "C" fn(*mut CollectionPrefix, *mut u8) =
        core::mem::transmute((*value).vtable.add(51).read());
    remove(value, item);
}

// 0x08129ab4 walks the selected collection, remembers the selected item's
// index, clears via slot +0x30, and reacquires that item if it was present.
unsafe fn clear_and_reacquire(state: *mut u8, mode: u32) {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0812_9ab4usize);
        call(state, mode);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (state, mode); panic!("unported input_sequence_clear_and_reacquire @ 0x08129ab4"); }
}

// 0x08129330 stores the signed index, updates offsets from the owning
// sequence and records the current millisecond timestamp.
unsafe fn reposition_item(item: *mut u8, index: i32) {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8, i32) = core::mem::transmute(0x0812_9330usize);
        call(item, index);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (item, index); panic!("unported input_sequence_item_reposition @ 0x08129330"); }
}

// 0x0812a074 copies primary bounds into alternate items, repositions them,
// resets remaining alternate items, then swaps the two collections.
unsafe fn commit_alternate(state: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0812_a074usize);
        call(state);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = state; panic!("unported input_sequence_commit_alternate @ 0x0812a074"); }
}

/// Handles an input-sequence event, returning whether it is recognized.
///
/// # Safety
/// `state` is aligned and writable through +0xd9. Collection words and
/// selected items must reference valid retail objects with callable vtables;
/// rendering events require a valid UI element and drawing context.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_dispatch(state: *mut u8, event: u32) -> u32 {
    match event {
        0x20 => {
            state.add(0xa1).write(5);
            let item = input_sequence_item_acquire(state, word(state, 0xb8).read() & 255, 0);
            word(state, 0xb0).write(item as u32);
        }
        0x21 => {
            let count = word(state, 0xb4).read();
            let item = word(state, 0xb0).read();
            if (count as i32) > 0 && item != 0 {
                let index = count - 1;
                word(state, 0xb4).write(index);
                input_sequence_item_clear_action(item as usize as *mut u32, index & 255);
            }
        }
        0x24 => {
            let mut index = word(state, 0xb4).read();
            while index < 32 {
                let item = word(state, 0xb0).read();
                if item != 0 {
                    input_sequence_item_clear_action(item as usize as *mut u32, index & 255);
                }
                index += 1;
            }
        }
        0x25..=0x27 => {
            if (state.add(0xa1).read() as u32).wrapping_sub(2) >= 3 {
                clear_collection(collection(state, 0xac));
                clear_collection(collection(state, 0xa8));
                word(state, 0xb0).write(0);
            }
            if (*collection(state, 0xa8)).count > 0 {
                state.add(0xd8).write(1);
            }
            if event == 0x25 {
                state.add(0xd9).write(1);
                state.add(0xa1).write(2);
            } else {
                state.add(0xa1).write((event - 0x23) as u8);
                state.add(0xd9).write(1);
            }
        }
        0x28 | 0x2a | 0x2b => {}
        0x29 | 0x2f => {
            if event == 0x29 {
                state.add(0xa1).write(6);
            } else {
                if state.add(0xa1).read() == 5 { commit_alternate(state); }
                state.add(0xa1).write(0);
            }
            input_sequence_item_acquire(state, word(state, 0xb8).read() & 255, 1);
        }
        0x2c => {
            let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
            cursor_init(&mut cursor, collection(state, 0xa8).cast::<Collection>());
            let mut item: *mut u8 = core::ptr::null_mut();
            while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
                let mut draw_state = core::mem::MaybeUninit::<[u32; 17]>::uninit();
                let draw = draw_state.as_mut_ptr().cast::<u8>();
                draw_state_construct(draw);
                draw_state_configure_for_element(state, draw);
                let mut bounds = core::mem::MaybeUninit::<Rect>::uninit();
                ui_offset_bounds(item, bounds.as_mut_ptr());
                let black = 0u32;
                draw_state_set_foreground_color(draw, core::ptr::addr_of!(black).cast());
                draw_state_fill_rect_foreground(draw, bounds.as_ptr());
            }
            clear_and_reacquire(state, 1);
            cursor_invalidate(&mut cursor);
        }
        0x2d => {
            let mode = state.add(0xa1).read() as u32;
            if mode.wrapping_sub(2) <= 2 {
                let mut remaining = mode - 1;
                if state.add(0xd9).read() != 0 {
                    word(state, 0xb8).write(word(state, 0xd4).read());
                    word(state, 0xb4).write(0);
                    state.add(0xd9).write(0);
                }
                let mut index = word(state, 0xb8).read().wrapping_sub(remaining);
                let item = input_sequence_find_item(state, (index & 255) as i32, 1);
                if !item.is_null() { remove_item(collection(state, 0xa8), item); }
                index = index.wrapping_add(1);
                while remaining != 0 {
                    let item = input_sequence_find_item(state, (index & 255) as i32, 1);
                    if !item.is_null() {
                        reposition_item(item, index.wrapping_sub(1) as u8 as i8 as i32);
                    }
                    index = index.wrapping_add(1);
                    remaining -= 1;
                }
                input_sequence_item_acquire(state, word(state, 0xb8).read() & 255, 1);
                word(state, 0xb4).write(0);
                state.add(0xd8).write(0);
            }
        }
        0x2e => clear_and_reacquire(state, 0),
        _ => return 0,
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[repr(C)]
    struct TestCollection {
        prefix: CollectionPrefix,
        clears: u32,
    }

    unsafe extern "C" fn clear(value: *mut CollectionPrefix) {
        let value = value.cast::<TestCollection>();
        (*value).clears += 1;
        (*value).prefix.count = 0;
    }

    #[test]
    fn unsupported_and_recognized_noops_preserve_state() {
        let mut state = [0xa5u32; 56];
        let before = state;
        for event in [0, 0x1f, 0x22, 0x23, 0x30, u32::MAX] {
            assert_eq!(unsafe { input_sequence_dispatch(state.as_mut_ptr().cast(), event) }, 0);
            assert_eq!(state, before);
        }
        for event in [0x28, 0x2a, 0x2b, 0x2d] {
            assert_eq!(unsafe { input_sequence_dispatch(state.as_mut_ptr().cast(), event) }, 1);
            assert_eq!(state, before);
        }
    }

    #[test]
    fn action_clear_signed_and_unsigned_boundaries_do_not_touch_selected_item() {
        let mut state = [0u32; 56];
        for count in [0, 0x8000_0000, u32::MAX] {
            state[0xb4 / 4] = count;
            state[0xb0 / 4] = 1; // Must not dereference this for a nonpositive count.
            assert_eq!(unsafe { input_sequence_dispatch(state.as_mut_ptr().cast(), 0x21) }, 1);
            assert_eq!(state[0xb4 / 4], count);
        }
        for count in [32, 0x8000_0000, u32::MAX] {
            state[0xb4 / 4] = count;
            assert_eq!(unsafe { input_sequence_dispatch(state.as_mut_ptr().cast(), 0x24) }, 1);
            assert_eq!(state[0xb4 / 4], count);
        }
        state[0xb0 / 4] = 0;
        state[0xb4 / 4] = 5;
        unsafe { input_sequence_dispatch(state.as_mut_ptr().cast(), 0x21); }
        assert_eq!(state[0xb4 / 4], 5);
    }

    #[test]
    fn window_transitions_clear_only_when_entering_from_outside_and_preserve_dirty_flag() {
        let Some(slab) = try_map_u32_slab(hints::INPUT_SEQUENCE_DISPATCH, 0x1000) else {
            assert!(note_missing_u32_fixture("input_sequence_dispatch"));
            return;
        };
        let mut vtable = [0usize; 52];
        vtable[12] = clear as *const () as usize;
        unsafe {
            let primary = slab.add(0x200).cast::<TestCollection>();
            let alternate = slab.add(0x300).cast::<TestCollection>();
            for old_mode in [0u8, 1, 2, 3, 4, 5, 6, 255] {
                for event in 0x25..=0x27 {
                    for count in [-1, 0, 2] {
                        core::ptr::write_bytes(slab, 0x6a, 0xe0);
                        primary.write(TestCollection { prefix: CollectionPrefix { vtable: vtable.as_ptr(), count }, clears: 0 });
                        alternate.write(TestCollection { prefix: CollectionPrefix { vtable: vtable.as_ptr(), count: 3 }, clears: 0 });
                        word(slab, 0xa8).write(primary as u32);
                        word(slab, 0xac).write(alternate as u32);
                        word(slab, 0xb0).write(0x1234);
                        slab.add(0xa1).write(old_mode);
                        slab.add(0xd8).write(0);
                        slab.add(0xd9).write(0);
                        assert_eq!(input_sequence_dispatch(slab, event), 1);
                        let outside = !(2..=4).contains(&old_mode);
                        assert_eq!((*primary).clears, outside as u32);
                        assert_eq!((*alternate).clears, outside as u32);
                        assert_eq!(word(slab, 0xb0).read(), if outside { 0 } else { 0x1234 });
                        assert_eq!(slab.add(0xa1).read(), (event - 0x23) as u8);
                        assert_eq!(slab.add(0xd9).read(), 1);
                        assert_eq!(slab.add(0xd8).read(), (!outside && count > 0) as u8);
                        assert_eq!(slab.add(0xa0).read(), 0x6a);
                        assert_eq!(slab.add(0xda).read(), 0x6a);
                        slab.add(0xd8).write(7);
                        (*primary).prefix.count = 0;
                        input_sequence_dispatch(slab, event);
                        assert_eq!(slab.add(0xd8).read(), 7);
                    }
                }
            }
        }
    }
}
