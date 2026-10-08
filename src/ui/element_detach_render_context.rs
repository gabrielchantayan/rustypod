//! Detach a UI element from its render context — `FUN_08146c68` @
//! **0x08146c68**, 44 bytes; next real function starts at 0x08146c94.
//! Raw ARM words verify two inbound plain BLs (0x081ddeec, 0x0828e618),
//! zero predicated inbound BLs. Body: zero plain BLs, one BLNE to
//! 0x0828cc00, and one tail B to 0x0826ec9c.
//!
//! If the target-width context link at +0x3c is nonzero, remove the element
//! from that context's collection using the resident 0x0828cc00 operation.
//! Clear the link after removal, then invalidate the element's full bounds.
//! The resident removal dispatches collection vtable slot +0x28 on the
//! embedded collection at context +0x7c and invalidates the removed element.
//!
//! Deliberate deviations: Rust expresses the final tail B as a call and
//! returns its element pointer. The unported removal remains a resident
//! call on device; hosts must supply an operation to the internal algorithm
//! when exercising an attached element. No algorithmic deviation intended.

use crate::ui::invalidate::ui_element_invalidate;

type RemoveElement = unsafe extern "C" fn(*mut u8, *mut u8);

#[inline(never)]
unsafe extern "C" fn render_context_remove_element(context: *mut u8, element: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let remove: RemoveElement = core::mem::transmute(0x0828_cc00usize);
        remove(context, element);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (context, element);
        panic!("resident render-context removal is unavailable on hosts");
    }
}

#[inline(always)]
unsafe fn detach_with(
    element: *mut u8,
    remove: RemoveElement,
    invalidate: unsafe extern "C" fn(*mut u8) -> *mut u8,
) -> *mut u8 {
    let link = element.add(0x3c).cast::<u32>();
    let context = link.read();
    if context != 0 {
        remove(context as usize as *mut u8, element);
    }
    link.write(0);
    invalidate(element)
}

/// # Safety
/// `element` must be a writable retail UI element with a valid target-width
/// context link and all fields required by whole-bounds invalidation. Any
/// linked context must support its embedded collection's removal operation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_detach_render_context(element: *mut u8) -> *mut u8 {
    detach_with(element, render_context_remove_element, ui_element_invalidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn remove(context: *mut u8, element: *mut u8) {
        let words = element.cast::<u32>();
        assert_eq!(context as usize, words.add(15).read() as usize);
        assert_eq!(words.read(), 0);
        words.write(1);
        // Removal may mutate the link; the caller must still clear it.
        words.add(15).write(0xdeadbeef);
    }

    unsafe extern "C" fn invalidate(element: *mut u8) -> *mut u8 {
        let words = element.cast::<u32>();
        assert_eq!(words.add(15).read(), 0);
        words.write(words.read() + 10);
        element
    }

    #[test]
    fn removal_observes_old_link_and_invalidation_observes_cleared_link() {
        for context in [0, 1, 0x80000000, u32::MAX] {
            let mut words = [0u32; 16];
            words[15] = context;
            let element = words.as_mut_ptr().cast();
            unsafe { assert_eq!(detach_with(element, remove, invalidate), element); }
            assert_eq!(words[0], if context == 0 { 10 } else { 11 });
            assert_eq!(words[15], 0);
            assert_eq!(&words[1..15], &[0; 14]);
        }
    }

    #[test]
    fn disconnected_hidden_element_returns_itself_without_changing_other_fields() {
        let mut words = [0u32; 0xa4 / 4];
        words[1] = 0x12345678;
        let original = words;
        let element = words.as_mut_ptr().cast();
        unsafe { assert_eq!(ui_element_detach_render_context(element), element); }
        assert_eq!(words, original);
    }
}
