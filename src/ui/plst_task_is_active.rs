//! 'plst' task activity predicate.
//!
//! - `plst_task_is_active` — original: `FUN_08061650` @ `0x08061650`
//!   (48 bytes; 3 direct `bl` call sites, all unconditional).

use super::plst_class_check::ui_element_is_plst_class;

const TASK_ELEMENT_WORD: usize = 0;
const TASK_ACTIVE_LINK_WORD: usize = 4;

/// plst_task_is_active — original: `FUN_08061650` @ `0x08061650`
/// (48 bytes).
///
/// Raw ARM starts with `movs r2,r0` at `0x08061650` and ends with
/// `pop {pc}` at `0x0806167c`; the next independent function starts at
/// `0x08061680`. Its only call is the already-ported
/// [`ui_element_is_plst_class`] at `0x080613e0`. Decoding every B/BL word in
/// `osos.dec` finds three inbound plain `bl` calls (`0x08048a14`,
/// `0x0805cdec`, and `0x0805d348`) and no predicated calls.
///
/// Algorithm: return 1 only when `task` is non-NULL, its word +0 target is a
/// 'plst'-class UI element, and its word +0x10 active link is nonzero. The
/// class check occurs before the active-link read, preserving the original's
/// short-circuiting access order.
///
/// Deliberate deviations: none. The stock `bl 0x080613e0` becomes the
/// already-ported class predicate; it retains the same target-width pointer
/// field interpretation and strict 0/1 result.
///
/// # Safety
///
/// `task` may be NULL. When non-NULL, it must be aligned and readable through
/// word +4. Its word +0 must be a target-width pointer suitable for
/// [`ui_element_is_plst_class`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_task_is_active(task: *mut u32) -> u32 {
    if task.is_null() {
        return 0;
    }
    let element = task.add(TASK_ELEMENT_WORD).read() as usize as *const u8;
    u32::from(ui_element_is_plst_class(element) != 0 && task.add(TASK_ACTIVE_LINK_WORD).read() != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const PLST_CLASS_TAG: u32 = 0x706c_7374;

    #[test]
    fn null_task_returns_zero() {
        assert_eq!(unsafe { plst_task_is_active(core::ptr::null_mut()) }, 0);
    }

    #[test]
    fn class_and_active_link_both_gate_activity() {
        let Some(element) = try_map_u32_slab(hints::PLST_TASK_IS_ACTIVE, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let element = element.cast::<u32>();
        unsafe {
            element.write(0x080d_9fb0);
            element.add(1).write(PLST_CLASS_TAG);
        }
        let mut task = [element as usize as u32, 0, 0, 0, 1];
        assert_eq!(unsafe { plst_task_is_active(task.as_mut_ptr()) }, 1);

        task[4] = 0;
        assert_eq!(unsafe { plst_task_is_active(task.as_mut_ptr()) }, 0);

        task[4] = 1;
        unsafe { element.add(1).write(0x7464_6174) };
        assert_eq!(unsafe { plst_task_is_active(task.as_mut_ptr()) }, 0);
    }
}
