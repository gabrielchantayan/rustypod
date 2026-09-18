//! `class_6280_refresh_ui` — original: `FUN_0811b9dc` @ **0x0811b9dc**.
//! True extent is 108 bytes, `0x0811b9dc..0x0811ba48`: the next function
//! starts at 0x0811ba48. Raw decoding finds four inbound plain `bl` call
//! sites, zero predicated inbound `bl` forms, and no inbound tail branches.
//! The body has two direct `bl` calls to `__rt_sdiv` and tail-branches to the
//! unported `FUN_0826dd8c`.
//!
//! # Algorithm
//!
//! Converts the class position at +0x20 into a marker: mode byte +0x2d equal
//! to 3 uses `(position - 76000) * 20 / 1000 + 18`; every other mode uses
//! `(position - 88000) * 14 / 1000 + 20`. It reads the UI element pointer at
//! +0x94 and, only when non-null, tail-dispatches the marker and the element's
//! word +0x80 to `FUN_0826dd8c`.
//!
//! # Deliberate deviations
//!
//! `FUN_0826dd8c` is not named or ported. Target builds call its verified
//! retail address; host tests use a recording seam. The original tail branch
//! is therefore an ordinary call, while arguments and the NULL early return
//! are preserved.

use core::ptr;

use crate::runtime::rt_div::__rt_sdiv;

const POSITION_OFFSET: usize = 0x20;
const MODE_OFFSET: usize = 0x2d;
const UI_ELEMENT_OFFSET: usize = 0x94;
const ELEMENT_POSITION_OFFSET: usize = 0x80;

type ElementRefresh = unsafe extern "C" fn(u32, i32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_element_refresh(element: u32, marker: i32, position: u32) {
    let refresh: ElementRefresh = core::mem::transmute(0x0826_dd8cusize);
    refresh(element, marker, position);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_refresh(_: u32, _: i32, _: u32) {}

static mut ELEMENT_REFRESH: ElementRefresh = {
    #[cfg(target_os = "none")]
    { retail_element_refresh }
    #[cfg(not(target_os = "none"))]
    { missing_element_refresh }
};

/// Refreshes the class-0x6280 UI element from its selected position.
///
/// # Safety
/// `view` must point to a readable object containing bytes through +0x97;
/// when its +0x94 target pointer is nonzero, it must name a readable element
/// containing the aligned word at +0x80.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6280_refresh_ui(view: *mut u8) {
    let position = ptr::read_volatile(view.add(POSITION_OFFSET).cast::<i32>());
    let marker = if ptr::read_volatile(view.add(MODE_OFFSET)) == 3 {
        __rt_sdiv(position.wrapping_sub(76_000).wrapping_mul(20), 1_000).wrapping_add(18)
    } else {
        __rt_sdiv(position.wrapping_sub(88_000).wrapping_mul(14), 1_000).wrapping_add(20)
    };
    let element = ptr::read_volatile(view.add(UI_ELEMENT_OFFSET).cast::<u32>());
    if element != 0 {
        let element_ptr = element as usize as *const u8;
        let element_position = ptr::read_volatile(element_ptr.add(ELEMENT_POSITION_OFFSET).cast::<u32>());
        ELEMENT_REFRESH(element, marker, element_position);
    }
}

#[cfg(test)]
pub static ELEMENT_REFRESH_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    static mut OBSERVED: (u32, i32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_refresh(element: u32, marker: i32, position: u32) {
        OBSERVED = (element, marker, position);
    }

    #[test]
    fn mode_three_uses_its_position_scale_and_forwards_element_word() {
        let _lock = ELEMENT_REFRESH_TEST_LOCK.lock();
        let Some(element) = try_map_u32_slab(hints::CLASS_6280_REFRESH_UI, 0x1000) else { return; };
        let mut view = [0u8; 0x98];
        unsafe {
            ptr::write_unaligned(view.as_mut_ptr().add(POSITION_OFFSET).cast::<i32>(), 77_000);
            *view.as_mut_ptr().add(MODE_OFFSET) = 3;
            ptr::write_unaligned(view.as_mut_ptr().add(UI_ELEMENT_OFFSET).cast::<u32>(), element as usize as u32);
            ptr::write_unaligned(element.add(ELEMENT_POSITION_OFFSET).cast::<u32>(), 0xdead_beef);
            ELEMENT_REFRESH = record_refresh;
            class_6280_refresh_ui(view.as_mut_ptr());
            assert_eq!(OBSERVED, (element as usize as u32, 38, 0xdead_beef));
            ELEMENT_REFRESH = missing_element_refresh;
        }
    }

    #[test]
    fn other_modes_use_their_scale_and_null_element_does_not_dispatch() {
        let _lock = ELEMENT_REFRESH_TEST_LOCK.lock();
        let mut view = [0u8; 0x98];
        unsafe {
            ptr::write_unaligned(view.as_mut_ptr().add(POSITION_OFFSET).cast::<i32>(), 89_000);
            *view.as_mut_ptr().add(MODE_OFFSET) = 2;
            OBSERVED = (1, 2, 3);
            ELEMENT_REFRESH = record_refresh;
            class_6280_refresh_ui(view.as_mut_ptr());
            assert_eq!(OBSERVED, (1, 2, 3));
            ELEMENT_REFRESH = missing_element_refresh;
        }
    }
}
