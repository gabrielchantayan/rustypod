//! `pool_deque_begin_cursor_set` — original: `FUN_081fbf78` @ **0x081fbf78**
//! (8 bytes; 5 verified direct `bl` call sites, all unconditional).
//!
//! The complete body is `str r1, [r0, #0x4c]; bx lr`: it replaces the
//! `begin.cur` word of a block-manager [`PoolBase`]'s embedded deque. The next
//! separately linked function starts at 0x081fbf80, confirming the 8-byte
//! extent. The firmware treats this word as a `u32` cursor value even though
//! the recovered host representation uses a pointer; this port preserves its
//! target word value with a pointer-sized cast. It does not NULL-check `this`,
//! matching the original.
//!
//! `pool_deque_begin_cursor_get` — original: `FUN_081fbf70` @ **0x081fbf70**
//! (8 bytes; 3 verified direct `bl` call sites, all unconditional).
//!
//! The complete body is `ldr r0, [r0, #0x4c]; bx lr`: it returns the
//! `begin.cur` word of a block-manager [`PoolBase`]'s embedded deque. The next
//! separately linked function starts at 0x081fbf78, confirming the 8-byte
//! extent. The firmware returns this pointer-shaped target word as a `u32`;
//! this port converts the recovered host pointer back to its target-width
//! value. It does not NULL-check `this`, matching the original.


use crate::heap::block_deque::PoolBase;

/// Replaces the embedded deque's begin-cursor word.
///
/// `this` must point to a valid [`PoolBase`], as required by the original
/// unchecked `str` at +0x4c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pool_deque_begin_cursor_set")]
pub unsafe extern "C" fn pool_deque_begin_cursor_set(this: *mut PoolBase, cursor: u32) {
    (*this).deque.begin.cur = cursor as *mut u8;
}

/// Returns the embedded deque's begin-cursor word.
///
/// `this` must point to a valid [`PoolBase`], as required by the original
/// unchecked `ldr` at +0x4c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pool_deque_begin_cursor_get")]
pub unsafe extern "C" fn pool_deque_begin_cursor_get(this: *const PoolBase) -> u32 {
    (*this).deque.begin.cur as usize as u32
}


#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn replaces_only_the_begin_cursor_word() {
        let mut object = MaybeUninit::<PoolBase>::zeroed();

        unsafe {
            let base = object.as_mut_ptr();
            (*base).deque.begin.seg_base = 0x1234_5678usize as *mut u8;
            (*base).deque.begin.seg_end = 0x8765_4321usize as *mut u8;
            for cursor in [0, 1, 0x8000_0000, u32::MAX] {
                pool_deque_begin_cursor_set(base, cursor);
                assert_eq!((*base).deque.begin.cur as usize, cursor as usize);
                assert_eq!((*base).deque.begin.seg_base as usize, 0x1234_5678);
                assert_eq!((*base).deque.begin.seg_end as usize, 0x8765_4321);
            }
        }
    }

    #[test]
    fn returns_the_begin_cursor_word_without_changing_it() {
        let mut object = MaybeUninit::<PoolBase>::zeroed();

        unsafe {
            let base = object.as_mut_ptr();
            (*base).deque.begin.seg_base = 0x1234_5678usize as *mut u8;
            (*base).deque.begin.seg_end = 0x8765_4321usize as *mut u8;
            for cursor in [0, 1, 0x8000_0000, u32::MAX] {
                (*base).deque.begin.cur = cursor as usize as *mut u8;
                assert_eq!(pool_deque_begin_cursor_get(base), cursor);
                assert_eq!((*base).deque.begin.cur as usize, cursor as usize);
                assert_eq!((*base).deque.begin.seg_base as usize, 0x1234_5678);
                assert_eq!((*base).deque.begin.seg_end as usize, 0x8765_4321);
            }
        }
    }
}
