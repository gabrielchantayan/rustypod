//! Relative scroll-position query for an opaque scrolling view.
//!
//! `view_scroll_position` — original: `FUN_0829c438` at load address
//! **0x0829c438** (36 bytes, `0x0829c438..0x0829c458`; the next sibling is
//! the independent `bx lr` at `0x0829c45c`).
//!
//! The function invokes the view's vtable slot at +0x114 with the unmodified
//! view pointer, then wrapping-subtracts the signed origin word at +0xac. It
//! therefore returns the view-relative scroll position. Decoding every ARM
//! B/BL word in `osos.dec` finds six direct callers, all unconditional `bl`:
//! 0x0816ac88, 0x0816afd4, 0x0816b01c, 0x0816b668, 0x0816b700, and
//! 0x0816b77c. There are no predicated calls or direct tail branches.
//!
//! Deliberate deviation: the vtable has native-width slots on host tests, so
//! callback pointers remain valid there; on the 32-bit target its queried slot
//! and the origin field remain exactly +0x114 and +0xac.

#[repr(C)]
struct ScrollableViewVtable {
    _reserved: [usize; 69],
    content_position: unsafe extern "C" fn(*mut u8) -> i32,
}

#[repr(C)]
struct ScrollableView {
    vtable: *const ScrollableViewVtable,
    _reserved: [u32; 42],
    content_origin: i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xb0] = [0; core::mem::size_of::<ScrollableView>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xac] = [0; core::mem::offset_of!(ScrollableView, content_origin)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x118] = [0; core::mem::size_of::<ScrollableViewVtable>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x114] = [0; core::mem::offset_of!(ScrollableViewVtable, content_position)];

/// Returns the callback-reported content position relative to the view origin.
///
/// # Safety
///
/// `view` must point to a valid scrolling-view object with a valid vtable and
/// callable +0x114 slot. The retail function has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_scroll_position(view: *mut u8) -> i32 {
    let scrollable_view = &*view.cast::<ScrollableView>();
    let content_position = ((*scrollable_view.vtable).content_position)(view);
    content_position.wrapping_sub(scrollable_view.content_origin)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(C)]
    struct Fixture {
        view: ScrollableView,
        callback_result: i32,
    }

    unsafe extern "C" fn fixture_content_position(view: *mut u8) -> i32 {
        (*view.cast::<Fixture>()).callback_result
    }

    fn fixture(content_origin: i32, callback_result: i32) -> Fixture {
        Fixture {
            view: ScrollableView {
                vtable: &ScrollableViewVtable {
                    _reserved: [0; 69],
                    content_position: fixture_content_position,
                },
                _reserved: [0; 42],
                content_origin,
            },
            callback_result,
        }
    }

    #[test]
    fn returns_the_callback_position_relative_to_the_origin() {
        let mut fixture = fixture(23, 53);

        assert_eq!(unsafe { view_scroll_position((&mut fixture.view as *mut ScrollableView).cast()) }, 30);
    }

    #[test]
    fn wraps_the_signed_subtraction_like_arm_sub() {
        let mut fixture = fixture(1, i32::MIN);

        assert_eq!(
            unsafe { view_scroll_position((&mut fixture.view as *mut ScrollableView).cast()) },
            i32::MAX
        );
    }
}
